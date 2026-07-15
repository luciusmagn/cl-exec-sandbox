(in-package #:cl-exec-sandbox)

;;;; -- Backend Capability Discovery --

(defparameter +linux-platform-read-roots+
  '(#P"/bin/" #P"/sbin/" #P"/usr/" #P"/etc/" #P"/lib/" #P"/lib64/"
    #P"/nix/store/" #P"/run/current-system/sw/")
  "System roots exposed by the Linux backend for a :MINIMAL read rule.")

(defun linux--path-components (path)
  "Return PATH's non-empty slash-separated components."
  (remove-if (lambda (component) (zerop (length component)))
             (uiop:split-string (uiop:native-namestring path)
                                :separator '(#\/))))

(defun linux--path-under-p (path root)
  "Return true when absolute PATH is ROOT or a descendant of ROOT."
  (let ((path-namestring (uiop:native-namestring path))
        (root-namestring
          (uiop:native-namestring (uiop:ensure-directory-pathname root))))
    (or (string= path-namestring
                 (string-right-trim "/" root-namestring))
        (uiop:string-prefix-p root-namestring path-namestring))))

(defun linux--executable-file-p (path)
  "Return true when PATH names an executable regular file."
  (let ((test-program
          (cond
            ((probe-file #P"/usr/bin/test") "/usr/bin/test")
            ((probe-file #P"/bin/test") "/bin/test")
            (t nil))))
    (and test-program
         (probe-file path)
         (not (uiop:directory-pathname-p (probe-file path)))
         (zerop
          (nth-value
           2
           (uiop:run-program
            (list test-program "-x" (uiop:native-namestring path))
            :ignore-error-status t
            :output nil
            :error-output nil))))))

(defun linux--path-directories ()
  "Return PATH entries as absolute directory pathnames."
  (loop for entry in (uiop:split-string (or (uiop:getenv "PATH") "")
                                        :separator '(#\:))
        when (plusp (length entry))
          collect (uiop:ensure-directory-pathname
                   (uiop:ensure-absolute-pathname entry (uiop:getcwd)))))

(defun linux--find-bwrap ()
  "Return a trusted system bubblewrap pathname, excluding the current directory."
  (loop for candidate in '(#P"/usr/bin/bwrap" #P"/bin/bwrap")
        when (linux--executable-file-p candidate)
          return (truename candidate)))

(defun linux--find-rg ()
  "Return the configured or PATH-resolved ripgrep pathname, excluding CWD."
  (let ((override (uiop:getenv "CL_EXEC_SANDBOX_RG"))
        (cwd (uiop:getcwd)))
    (or (when (and override (linux--executable-file-p (pathname override)))
          (truename override))
        (loop for candidate in '(#P"/usr/bin/rg" #P"/bin/rg")
              when (linux--executable-file-p candidate)
                return (truename candidate))
        (loop for directory in (linux--path-directories)
              for candidate = (merge-pathnames "rg" directory)
              when (and (not (linux--path-under-p candidate cwd))
                        (linux--executable-file-p candidate))
                return (truename candidate)))))

(defun linux--find-helper ()
  "Return the installed internal Linux helper pathname, or NIL."
  (let* ((override (uiop:getenv "CL_EXEC_SANDBOX_HELPER"))
         (candidate
           (if override
               (pathname override)
               (asdf:system-relative-pathname
                :cl-exec-sandbox
                #P"build/cl-exec-sandbox-helper"))))
    (when (linux--executable-file-p candidate)
      (truename candidate))))

(defun sandbox-capabilities ()
  "Return a portable plist describing the current host sandbox backend."
  (let ((bwrap (and (member :linux *features*) (linux--find-bwrap)))
        (rg (and (member :linux *features*) (linux--find-rg)))
        (helper (and (member :linux *features*) (linux--find-helper))))
    (list :platform (cond
                      ((member :linux *features*) :linux)
                      ((member :darwin *features*) :macos)
                      ((member :windows *features*) :windows)
                      (t :unknown))
          :backend (and bwrap :bubblewrap)
          :available-p (not (null bwrap))
          :filesystem-read-write-deny (not (null bwrap))
          :filesystem-deny-globs (and (not (null bwrap)) (not (null rg)))
          :nested-overrides (not (null bwrap))
          :process-namespaces (not (null bwrap))
          :network-enabled t
          :network-isolated (and (not (null bwrap)) (not (null helper)))
          :network-proxy-only (and (not (null bwrap)) (not (null helper)))
          :seccomp (not (null helper)))))

(defun sandbox-supported-p (&optional (capability :available-p))
  "Return true when the host reports CAPABILITY in SANDBOX-CAPABILITIES."
  (not (null (getf (sandbox-capabilities) capability))))


;;;; -- Resolved Rules --

(defstruct (resolved-filesystem-rule
            (:constructor linux--resolved-rule (path access origin)))
  "One absolute filesystem rule after special-path and glob expansion."
  (path #P"/" :type pathname)
  (access :read :type (member :read :write :deny))
  (origin :path :type keyword))

(defun linux--absolute-path (path cwd)
  "Resolve PATH against CWD without requiring it to exist."
  (uiop:ensure-absolute-pathname (pathname path) cwd))

(defun linux--safe-relative-subpath (subpath)
  "Return SUBPATH as a relative pathname or signal a policy error."
  (let ((pathname (pathname subpath)))
    (when (or (uiop:absolute-pathname-p pathname)
              (member :up (pathname-directory pathname)))
      (error 'sandbox-policy-error
             :message (format nil "Workspace subpath must stay relative: ~A" subpath)))
    pathname))

(defun linux--special-paths (rule policy cwd)
  "Expand special RULE into absolute paths for POLICY and CWD."
  (case (filesystem-rule-path rule)
    (:root
     (list #P"/"))
    (:minimal
     (remove-if-not #'probe-file +linux-platform-read-roots+))
    (:workspace-roots
     (let ((subpath (and (filesystem-rule-subpath rule)
                         (linux--safe-relative-subpath
                          (filesystem-rule-subpath rule)))))
       (mapcar (lambda (root)
                 (if subpath
                     (merge-pathnames subpath root)
                     root))
               (sandbox-policy-workspace-roots policy))))
    (:tmpdir
     (list (uiop:ensure-directory-pathname
            (linux--absolute-path
             (or (uiop:getenv "TMPDIR") (uiop:temporary-directory)) cwd))))
    (:slash-tmp
     (list #P"/tmp/"))))

(defun linux--run-rg-glob (pattern root maximum-depth)
  "Return existing paths below ROOT matching git-style PATTERN through ripgrep."
  (let ((rg (linux--find-rg)))
    (unless rg
      (error 'sandbox-unavailable
             :message "Deny-glob expansion requires ripgrep."
             :capability :filesystem-deny-globs))
    (let ((arguments (list (uiop:native-namestring rg)
                           "--files" "--hidden" "--no-ignore" "--null"
                           "--glob" pattern)))
      (when maximum-depth
        (setf arguments
              (append arguments
                      (list "--max-depth" (write-to-string maximum-depth)))))
      (setf arguments
            (append arguments (list "--" (uiop:native-namestring root))))
      (multiple-value-bind (output error-output status)
          (uiop:run-program arguments
                            :output :string
                            :error-output :string
                            :ignore-error-status t)
        (declare (ignore error-output))
        (unless (member status '(0 1))
          (error 'sandbox-policy-error
                 :message (format nil "Could not expand deny glob ~S below ~A."
                                  pattern root)))
        (if (zerop (length output))
            nil
            (loop for path in (uiop:split-string output :separator (list #\Null))
                  when (plusp (length path))
                    collect (linux--absolute-path path root)))))))

(defun linux--expand-glob-rule (rule policy cwd)
  "Expand one deny-glob RULE below POLICY's project roots or CWD."
  (let ((roots (or (sandbox-policy-workspace-roots policy) (list cwd))))
    (loop for root in roots
          append (linux--run-rg-glob
                  (filesystem-rule-path rule)
                  root
                  (sandbox-policy-glob-scan-maximum-depth policy)))))

(defun linux--metadata-rules (policy)
  "Return read-only metadata rules nested below writable project roots."
  (loop for root in (sandbox-policy-workspace-roots policy)
        append
        (loop for name in (sandbox-policy-protected-metadata-names policy)
              collect (linux--resolved-rule
                       (merge-pathnames
                        (uiop:ensure-directory-pathname name)
                        root)
                       :read
                       :protected-metadata))))

(defun linux--resolve-rules (policy cwd)
  "Return POLICY's absolute rules sorted from broadest to most specific."
  (let ((rules nil))
    (when (eq (sandbox-policy-filesystem-kind policy) :unrestricted)
      (push (linux--resolved-rule #P"/" :write :unrestricted) rules))
    (dolist (rule (sandbox-policy-filesystem-rules policy))
      (ecase (filesystem-rule-kind rule)
        (:path
         (push (linux--resolved-rule
                (linux--absolute-path (filesystem-rule-path rule) cwd)
                (filesystem-rule-access rule)
                :path)
               rules))
        (:special
         (dolist (path (linux--special-paths rule policy cwd))
           (push (linux--resolved-rule path
                                       (filesystem-rule-access rule)
                                       :special)
                 rules)))
        (:glob
         (dolist (path (linux--expand-glob-rule rule policy cwd))
           (push (linux--resolved-rule path :deny :glob) rules)))))
    (setf rules (append rules (linux--metadata-rules policy)))
    (stable-sort
     rules
     (lambda (left right)
       (let ((left-depth (length (linux--path-components
                                  (resolved-filesystem-rule-path left))))
             (right-depth (length (linux--path-components
                                   (resolved-filesystem-rule-path right)))))
         (if (= left-depth right-depth)
             (< (position (resolved-filesystem-rule-access left)
                          '(:read :write :deny))
                (position (resolved-filesystem-rule-access right)
                          '(:read :write :deny)))
             (< left-depth right-depth)))))))


;;;; -- Bubblewrap Plan --

(defclass sandbox-plan ()
  ((program
    :initarg :program
    :reader sandbox-plan-program
    :type pathname
    :documentation "The host program that starts the planned command.")
   (arguments
    :initarg :arguments
    :reader sandbox-plan-arguments
    :type list
    :documentation "Arguments passed to PROGRAM.")
   (environment
   :initarg :environment
    :reader sandbox-plan-environment
    :type list
    :documentation "Environment entries passed to PROGRAM as KEY=VALUE strings.")
   (environment-provided-p
    :initarg :environment-provided-p
    :reader sandbox-plan-environment-provided-p
    :type boolean
    :documentation "Whether execution should replace rather than inherit the host environment.")
   (working-directory
    :initarg :working-directory
    :reader sandbox-plan-working-directory
    :type pathname
    :documentation "The host working directory used for a direct launch.")
   (cleanup-paths
    :initarg :cleanup-paths
    :reader sandbox-plan-cleanup-paths
    :type list
    :documentation "Transient host paths removed after execution when still safe."))
  (:documentation "A fully validated native launch plan and its cleanup obligations."))

(defun linux--append-target-parent-arguments (arguments path)
  "Append --dir operations ensuring PATH's parent components exist in a minimal root."
  (let ((components (butlast (linux--path-components path)))
        (current ""))
    (dolist (component components arguments)
      (setf current (concatenate 'string current "/" component))
      (setf arguments (append arguments (list "--dir" current))))))

(defun linux--root-access (rules)
  "Return the final access of an exact root rule in RULES, or NIL."
  (let ((matches
          (remove-if-not
           (lambda (rule)
             (string= (uiop:native-namestring
                       (resolved-filesystem-rule-path rule))
                      "/"))
           rules)))
    (when matches
      (resolved-filesystem-rule-access (first (last matches))))))

(defun linux--existing-path-p (path)
  "Return true when PATH exists without requiring directory syntax agreement."
  (not (null (probe-file path))))

(defun linux--writable-descendants (rule rules)
  "Return writable RULES strictly below denied directory RULE."
  (let ((path (resolved-filesystem-rule-path rule)))
    (remove-if-not
     (lambda (candidate)
       (let ((candidate-path (resolved-filesystem-rule-path candidate)))
         (and (eq (resolved-filesystem-rule-access candidate) :write)
              (not (equal candidate-path path))
              (linux--path-under-p candidate-path path))))
     rules)))

(defun linux--append-descendant-parent-arguments (arguments descendant root)
  "Create missing parents of DESCENDANT beneath a freshly masked ROOT."
  (let ((directories nil)
        (current (if (uiop:directory-pathname-p descendant)
                     descendant
                     (uiop:pathname-parent-directory-pathname descendant))))
    (loop while (and current
                     (linux--path-under-p current root)
                     (not (equal current root)))
          do (push current directories)
             (setf current (uiop:pathname-parent-directory-pathname current)))
    (dolist (directory directories arguments)
      (setf arguments
            (append arguments
                    (list "--dir" (uiop:native-namestring directory)))))))

(defun linux--append-directory-mask (arguments target permissions descendants)
  "Append a read-only empty directory mask at TARGET with PERMISSIONS."
  (setf arguments
        (append arguments (list "--perms" permissions "--tmpfs" target)))
  (dolist (descendant descendants)
    (setf arguments
          (linux--append-descendant-parent-arguments
           arguments
           (resolved-filesystem-rule-path descendant)
           (pathname target))))
  (append arguments (list "--remount-ro" target)))

(defun linux--append-rule-arguments
    (arguments rule minimal-root-p deny-file-mask rules)
  "Append RULE's effective mount operation to ARGUMENTS."
  (let* ((path (resolved-filesystem-rule-path rule))
         (target (uiop:native-namestring path))
         (source (and (probe-file path) target)))
    (when minimal-root-p
      (setf arguments (linux--append-target-parent-arguments arguments path)))
    (case (resolved-filesystem-rule-access rule)
      (:read
       (when source
         (setf arguments (append arguments (list "--ro-bind" source target)))))
      (:write
       (when source
         (setf arguments (append arguments (list "--bind" source target)))))
      (:deny
       (if (or (not (probe-file path))
               (uiop:directory-pathname-p (probe-file path)))
           (let ((descendants (linux--writable-descendants rule rules)))
             (setf arguments
                   (linux--append-directory-mask
                    arguments target
                    (if descendants "111" "000")
                    descendants)))
           (setf arguments
                 (append arguments
                         (list "--ro-bind"
                               (uiop:native-namestring deny-file-mask)
                               target)))))
      (otherwise
       (error 'sandbox-policy-error
              :message "Unknown resolved filesystem access.")))
    (when (and (eq (resolved-filesystem-rule-origin rule) :protected-metadata)
               (not (probe-file path)))
      (setf arguments
            (linux--append-directory-mask arguments target "555" nil)))
    arguments))

(defun linux--temporary-mask-file ()
  "Create and return a mode-000 host file suitable for denying one sandbox path."
  (loop
    for candidate =
      (merge-pathnames
       (format nil "cl-exec-sandbox-mask-~36R-~36R"
               (get-universal-time) (random most-positive-fixnum))
       (uiop:temporary-directory))
    unless (probe-file candidate)
      do (with-open-file (stream candidate
                                  :direction :output
                                  :if-does-not-exist :create
                                  :if-exists :error)
           (file-position stream 0))
         (multiple-value-bind (output error-output status)
             (uiop:run-program (list "chmod" "000"
                                     (uiop:native-namestring candidate))
                               :output :string
                               :error-output :string
                               :ignore-error-status t)
           (declare (ignore output error-output))
           (unless (zerop status)
             (delete-file candidate)
             (error 'sandbox-unavailable
                    :message "Could not create a deny-path mask file."
                    :capability :filesystem-deny)))
         (return candidate)))

(defun linux--base-arguments (policy cwd root-access environment clear-environment-p)
  "Return namespace, base filesystem, environment, and working-directory arguments."
  (let ((arguments (list "--die-with-parent" "--new-session")))
    (when (sandbox-policy-isolate-processes-p policy)
      (setf arguments
            (append arguments
                    (list "--unshare-user" "--unshare-pid"
                          "--unshare-ipc" "--unshare-uts"))))
    (unless (eq (sandbox-policy-network policy) :enabled)
      (setf arguments (append arguments (list "--unshare-net"))))
    (if root-access
        (setf arguments
              (append arguments
                      (list (if (eq root-access :write) "--bind" "--ro-bind")
                            "/" "/")))
        (progn
          (setf arguments (append arguments (list "--tmpfs" "/")))
          (dolist (root +linux-platform-read-roots+)
            (when (probe-file root)
              (setf arguments
                    (linux--append-target-parent-arguments arguments root)
                    arguments
                    (append arguments
                            (list "--ro-bind"
                                  (uiop:native-namestring root)
                                  (uiop:native-namestring root))))))))
    (setf arguments (append arguments (list "--dev" "/dev")))
    (when (sandbox-policy-mount-proc-p policy)
      (setf arguments (append arguments (list "--proc" "/proc"))))
    (when clear-environment-p
      (setf arguments (append arguments (list "--clearenv"))))
    (dolist (entry environment)
      (let ((separator (position #\= entry)))
        (unless separator
          (error 'sandbox-policy-error
                 :message (format nil "Malformed environment entry: ~S" entry)))
        (setf arguments
              (append arguments
                      (list "--setenv"
                            (subseq entry 0 separator)
                            (subseq entry (1+ separator)))))))
    (append arguments (list "--chdir" (uiop:native-namestring cwd)))))

(defun linux--bubblewrap-plan
    (program arguments policy cwd environment clear-environment-p)
  "Return a bubblewrap launch plan for PROGRAM and ARGUMENTS under POLICY."
  (let ((bwrap (linux--find-bwrap))
        (helper (unless (eq (sandbox-policy-network policy) :enabled)
                  (linux--find-helper))))
    (unless bwrap
      (error 'sandbox-unavailable
             :message "A restricted Linux sandbox requires bubblewrap on trusted PATH."
             :capability :bubblewrap))
    (when (and (not (eq (sandbox-policy-network policy) :enabled))
               (not helper))
      (error 'sandbox-unavailable
             :message "Restricted networking requires the cl-exec-sandbox Linux helper."
             :capability :seccomp-helper))
    (let* ((rules (linux--resolve-rules policy cwd))
           (root-access (linux--root-access rules))
           (minimal-root-p (null root-access))
           (deny-file-mask
             (when (find-if
                    (lambda (rule)
                      (let ((path (resolved-filesystem-rule-path rule)))
                        (and (eq (resolved-filesystem-rule-access rule) :deny)
                             (probe-file path)
                             (not (uiop:directory-pathname-p
                                   (probe-file path))))))
                    rules)
               (linux--temporary-mask-file)))
           (bwrap-arguments
             (linux--base-arguments policy cwd root-access
                                    environment clear-environment-p)))
      (when (and helper minimal-root-p)
        (setf bwrap-arguments
              (linux--append-target-parent-arguments bwrap-arguments helper)
              bwrap-arguments
              (append bwrap-arguments
                      (list "--ro-bind"
                            (uiop:native-namestring helper)
                            (uiop:native-namestring helper)))))
      (dolist (rule rules)
        (unless (string= (uiop:native-namestring
                          (resolved-filesystem-rule-path rule))
                         "/")
          (setf bwrap-arguments
                (linux--append-rule-arguments
                 bwrap-arguments
                 rule
                 minimal-root-p
                 deny-file-mask
                 rules))))
      (let* ((network (sandbox-policy-network policy))
             (inner-command
               (if helper
                   (append (list (uiop:native-namestring helper)
                                 "inner"
                                 (string-downcase (symbol-name network))
                                 "--"
                                 (uiop:native-namestring program))
                           arguments)
                   (cons (uiop:native-namestring program) arguments)))
             (command (append bwrap-arguments (list "--") inner-command))
             (synthetic-targets
               (loop for rule in rules
                     for path = (resolved-filesystem-rule-path rule)
                     when (and (not (probe-file path))
                               (or (eq (resolved-filesystem-rule-access rule) :deny)
                                   (eq (resolved-filesystem-rule-origin rule)
                                       :protected-metadata)))
                       collect path))
             (cleanup-paths
               (append synthetic-targets
                       (when deny-file-mask (list deny-file-mask)))))
        (if (eq network :proxy-only)
            (make-instance 'sandbox-plan
                           :program helper
                           :arguments (append (list "proxy-outer" "--"
                                                   (uiop:native-namestring bwrap))
                                              command)
                           :environment environment
                           :environment-provided-p (or (not (null environment))
                                                       clear-environment-p)
                           :working-directory cwd
                           :cleanup-paths cleanup-paths)
            (make-instance 'sandbox-plan
                           :program bwrap
                           :arguments command
                           :environment nil
                           :environment-provided-p nil
                           :working-directory cwd
                           :cleanup-paths cleanup-paths))))))

(defun sandbox-build-plan
    (program arguments
     &key policy working-directory environment clear-environment-p)
  "Build a validated native launch plan for PROGRAM and ARGUMENTS."
  (unless (typep policy 'sandbox-policy)
    (error 'sandbox-policy-error
           :message "SANDBOX-BUILD-PLAN requires a SANDBOX-POLICY."))
  (unless (and (listp arguments) (every #'stringp arguments))
    (error 'sandbox-policy-error
           :message "Command arguments must be a list of strings."))
  (let* ((cwd (policy--absolute-directory
               (or working-directory (uiop:getcwd))
               "The command working directory"))
         (program-path
           (let ((pathname (pathname program)))
             (if (uiop:absolute-pathname-p pathname)
                 pathname
                 (or (loop for directory in (linux--path-directories)
                           for candidate = (merge-pathnames pathname directory)
                           when (linux--executable-file-p candidate)
                             return (truename candidate))
                     (error 'sandbox-execution-error
                            :message (format nil "Could not find executable ~A." program)
                            :command (cons program arguments)))))))
    (cond
      ((eq (sandbox-policy-filesystem-kind policy) :external)
       (make-instance 'sandbox-plan
                      :program program-path
                      :arguments arguments
                      :environment environment
                      :environment-provided-p (or (not (null environment))
                                                  clear-environment-p)
                      :working-directory cwd
                      :cleanup-paths nil))
      ((and (eq (sandbox-policy-filesystem-kind policy) :unrestricted)
            (eq (sandbox-policy-network policy) :enabled))
       (make-instance 'sandbox-plan
                      :program program-path
                      :arguments arguments
                      :environment environment
                      :environment-provided-p (or (not (null environment))
                                                  clear-environment-p)
                      :working-directory cwd
                      :cleanup-paths nil))
      ((member :linux *features*)
       (linux--bubblewrap-plan program-path arguments policy cwd
                               environment clear-environment-p))
      (t
       (error 'sandbox-unavailable
              :message "No sandbox backend is available for this operating system."
              :capability :platform-backend)))))
