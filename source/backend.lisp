(in-package #:cl-exec-sandbox)

;;;; -- Backend Capability Discovery --

(defun sandbox-capabilities ()
  "Return a portable plist describing the current host sandbox backend."
  (let ((bwrap (and (member :linux *features*) (linux--find-bwrap)))
        (rg (and (member :linux *features*) (rules--find-rg)))
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


;;;; -- Plan Dispatch --

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
                 (or (loop for directory in (path--directories)
                           for candidate = (merge-pathnames pathname directory)
                           when (path--executable-file-p candidate)
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
