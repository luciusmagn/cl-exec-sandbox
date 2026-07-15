(in-package #:cl-exec-sandbox/tests)

(defvar *test-count* 0
  "The number of assertions completed by the current test run.")

(defun test-assert (condition description)
  "Require CONDITION and count it as DESCRIPTION."
  (unless condition
    (error "Test failed: ~A" description))
  (incf *test-count*)
  t)

(defun tests--temporary-root ()
  "Create and return a fresh temporary test directory."
  (let ((root
          (merge-pathnames
           (format nil "cl-exec-sandbox-test-~36R-~36R/"
                   (get-universal-time) (random most-positive-fixnum))
           (uiop:temporary-directory))))
    (ensure-directories-exist root)
    root))

(defun tests--write (path text)
  "Write TEXT to PATH and return PATH."
  (ensure-directories-exist path)
  (with-open-file (stream path
                          :direction :output
                          :if-does-not-exist :create
                          :if-exists :supersede)
    (write-string text stream))
  path)

(defun test-policy-validation ()
  "Test policy presets, malformed rules, and capability discovery."
  (let ((policy
          (workspace-write-sandbox-policy
           :workspace-roots (list (uiop:getcwd)))))
    (test-assert (eq (sandbox-policy-network policy) :isolated)
                 "workspace-write defaults to isolated networking")
    (test-assert (= (length (sandbox-policy-filesystem-rules policy)) 4)
                 "workspace-write grants root read, project write, and temp writes")
    (test-assert
     (handler-case
         (progn
           (make-filesystem-rule :kind :glob :path "*.key" :access :read)
           nil)
       (sandbox-policy-error ()
         t))
     "glob rules reject positive access")
    (test-assert (getf (sandbox-capabilities) :filesystem-read-write-deny)
                 "Linux capability discovery finds bubblewrap"))
  nil)

(defun test-read-only-enforcement ()
  "Test a read-only policy permits reads and rejects host writes."
  (let* ((root (tests--temporary-root))
         (file (tests--write (merge-pathnames "value.txt" root) "before"))
         (policy (read-only-sandbox-policy)))
    (unwind-protect
         (let ((result
                 (run-sandboxed
                  "/bin/sh"
                  (list "-c"
                        (format nil "cat ~A; printf after > ~A"
                                (uiop:escape-shell-token
                                 (uiop:native-namestring file))
                                (uiop:escape-shell-token
                                 (uiop:native-namestring file))))
                  :policy policy
                  :working-directory root)))
           (test-assert (not (zerop (sandbox-result-exit-code result)))
                        "read-only execution rejects a write")
           (test-assert (search "before" (sandbox-result-output result))
                        "read-only execution still permits a read")
           (test-assert (string= (uiop:read-file-string file) "before")
                        "the rejected write leaves the host file unchanged"))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore)))
  nil)

(defun test-workspace-write-enforcement ()
  "Test workspace writes, outside rejection, and protected metadata carve-outs."
  (let* ((root (tests--temporary-root))
         (outside (tests--temporary-root))
         (git-directory (merge-pathnames ".git/" root))
         (git-file (tests--write (merge-pathnames "config" git-directory) "safe"))
         (workspace-file (merge-pathnames "created.txt" root))
         (outside-file (merge-pathnames "blocked.txt" outside))
         (policy
           (workspace-write-sandbox-policy :workspace-roots (list root)
                                           :write-tmpdir-p nil
                                           :write-slash-tmp-p nil)))
    (unwind-protect
         (let ((result
                 (run-sandboxed
                  "/bin/sh"
                  (list
                   "-c"
                   (format nil
                           "printf yes > ~A; printf no > ~A; printf bad > ~A"
                           (uiop:escape-shell-token
                            (uiop:native-namestring workspace-file))
                           (uiop:escape-shell-token
                            (uiop:native-namestring outside-file))
                           (uiop:escape-shell-token
                            (uiop:native-namestring git-file))))
                  :policy policy
                  :working-directory root)))
           (test-assert (probe-file workspace-file)
                        "workspace-write publishes a file below the project root")
           (test-assert (not (probe-file outside-file))
                        "workspace-write rejects a file outside the project root")
           (test-assert (string= (uiop:read-file-string git-file) "safe")
                        "protected metadata remains read-only")
           (test-assert (not (zerop (sandbox-result-exit-code result)))
                        "a rejected write is visible in the command status"))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore)
      (uiop:delete-directory-tree outside :validate t :if-does-not-exist :ignore)))
  nil)

(defun test-missing-protected-metadata ()
  "Test a missing protected metadata path cannot be created or left behind."
  (let* ((root (tests--temporary-root))
         (metadata (merge-pathnames ".agents/" root))
         (policy
           (workspace-write-sandbox-policy :workspace-roots (list root)
                                           :write-tmpdir-p nil
                                           :write-slash-tmp-p nil)))
    (unwind-protect
         (let ((result
                 (run-sandboxed "/bin/sh" '("-c" "mkdir .agents")
                                :policy policy
                                :working-directory root)))
           (test-assert (not (zerop (sandbox-result-exit-code result)))
                        "missing protected metadata rejects creation")
           (test-assert (not (probe-file metadata))
                        "synthetic metadata target is removed after execution"))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore)))
  nil)

(defun test-deny-and-nested-override ()
  "Test deny masks and a more-specific writable child below a denied parent."
  (let* ((root (tests--temporary-root))
         (blocked (merge-pathnames "blocked/" root))
         (allowed (merge-pathnames "allowed/" blocked))
         (secret (tests--write (merge-pathnames "secret.txt" blocked) "secret"))
         (output (merge-pathnames "new.txt" allowed)))
    (ensure-directories-exist output)
    (let ((policy
            (make-sandbox-policy
             :workspace-roots (list root)
             :filesystem-rules
             (list
              (make-filesystem-rule :kind :special :path :root :access :read)
              (make-filesystem-rule :kind :path :path root :access :write)
              (make-filesystem-rule :kind :path :path blocked :access :deny)
              (make-filesystem-rule :kind :path :path allowed :access :write)))))
      (unwind-protect
           (let ((result
                   (run-sandboxed
                    "/bin/sh"
                    (list "-c"
                          (format nil "cat ~A 2>/dev/null || true; printf ok > ~A"
                                  (uiop:escape-shell-token
                                   (uiop:native-namestring secret))
                                  (uiop:escape-shell-token
                                   (uiop:native-namestring output))))
                    :policy policy
                    :working-directory root)))
             (test-assert (not (search "secret" (sandbox-result-output result)))
                          "an exact deny masks readable content")
             (test-assert (string= (uiop:read-file-string output) "ok")
                          "a narrower write rule reopens a denied parent"))
        (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore))))
  nil)

(defun test-deny-glob ()
  "Test a deny glob masks matching files without masking other project files."
  (let* ((root (tests--temporary-root))
         (secret (tests--write (merge-pathnames "private.key" root) "secret"))
         (public (tests--write (merge-pathnames "public.txt" root) "public"))
         (policy
           (make-sandbox-policy
            :workspace-roots (list root)
            :filesystem-rules
            (list
             (make-filesystem-rule :kind :special :path :root :access :read)
             (make-filesystem-rule :kind :path :path root :access :write)
             (make-filesystem-rule :kind :glob :path "*.key" :access :deny)))))
    (unwind-protect
         (let ((result
                 (run-sandboxed
                  "/bin/sh"
                  (list "-c"
                        (format nil "cat ~A 2>/dev/null || true; cat ~A"
                                (uiop:escape-shell-token
                                 (uiop:native-namestring secret))
                                (uiop:escape-shell-token
                                 (uiop:native-namestring public))))
                  :policy policy
                  :working-directory root)))
           (test-assert (string= (sandbox-result-output result) "public")
                        "deny glob hides only matching content"))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore)))
  nil)

(defun test-unrestricted-filesystem-with-isolated-network ()
  "Test network isolation does not accidentally narrow an unrestricted filesystem."
  (let* ((root (tests--temporary-root))
         (output (merge-pathnames "created.txt" root))
         (result
           (run-sandboxed
            "/bin/sh"
            (list "-c"
                  (format nil "printf ok > ~A"
                          (uiop:escape-shell-token
                           (uiop:native-namestring output))))
            :policy (unrestricted-sandbox-policy :network :isolated))))
    (unwind-protect
         (progn
           (test-assert (zerop (sandbox-result-exit-code result))
                        "unrestricted filesystem command succeeds")
           (test-assert (string= (uiop:read-file-string output) "ok")
                        "unrestricted filesystem stays writable"))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore)))
  nil)

(defun test-external-execution-context ()
  "Test direct execution honors its working directory and explicit environment."
  (let* ((root (tests--temporary-root))
         (result
           (run-sandboxed
            "/bin/sh" '("-c" "printf '%s|%s' \"$PWD\" \"$VALUE\"")
            :policy (external-sandbox-policy)
            :working-directory root
            :environment '("VALUE=present"))))
    (unwind-protect
         (test-assert
          (string= (sandbox-result-output result)
                   (format nil "~A|present"
                           (string-right-trim
                            "/"
                            (uiop:native-namestring root))))
          "direct execution applies working directory and environment")
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore)))
  nil)

(defun test-timeout ()
  "Test deadline supervision terminates a sandbox process."
  (let ((result
          (run-sandboxed "/bin/sh" '("-c" "sleep 5")
                         :policy (read-only-sandbox-policy)
                         :timeout 0.05)))
    (test-assert (sandbox-result-timed-out-p result)
                 "a command exceeding its deadline is marked timed out")
    (test-assert (< (sandbox-result-real-seconds result) 2)
                 "deadline supervision returns promptly"))
  nil)

(defun test-isolated-network-seccomp ()
  "Test restricted networking denies Internet socket creation with seccomp."
  (let ((result
          (run-sandboxed
           "/bin/bash"
           '("-c" "exec 3<>/dev/tcp/127.0.0.1/1")
           :policy (read-only-sandbox-policy))))
    (test-assert (not (zerop (sandbox-result-exit-code result)))
                 "isolated networking rejects an Internet socket")
    (test-assert (search "Operation not permitted"
                         (sandbox-result-error-output result)
                         :test #'char-equal)
                 "isolated networking reports a seccomp denial"))
  nil)

(defun tests--start-proxy-server ()
  "Return a one-shot loopback proxy test socket, thread, and allocated port."
  (let ((listener
          (make-instance 'sb-bsd-sockets:inet-socket
                         :type :stream
                         :protocol :tcp)))
    (sb-bsd-sockets:socket-bind listener #(127 0 0 1) 0)
    (sb-bsd-sockets:socket-listen listener 1)
    (let ((port (nth-value 1 (sb-bsd-sockets:socket-name listener))))
      (values
       listener
       (sb-thread:make-thread
        (lambda ()
          (let* ((client (sb-bsd-sockets:socket-accept listener))
                 (stream
                   (sb-bsd-sockets:socket-make-stream
                    client
                    :input t
                    :output t
                    :element-type 'character
                    :external-format :utf-8
                    :buffering :none)))
            (unwind-protect
                 (progn
                   (write-string "pong" stream)
                   (finish-output stream))
              (close stream))))
        :name "cl-exec-sandbox proxy test server")
       port))))

(defun test-managed-proxy-network ()
  "Test proxy-only networking reaches a loopback proxy and rewrites its URL."
  (multiple-value-bind (server thread port)
      (tests--start-proxy-server)
    (unwind-protect
         (let ((result
                 (run-sandboxed
                  "/bin/bash"
                  '("-c"
                    "port=${HTTP_PROXY##*:}; exec 3<>/dev/tcp/127.0.0.1/$port; IFS= read -r -n 4 reply <&3; printf %s \"$reply\"")
                  :policy (read-only-sandbox-policy :network :proxy-only)
                  :environment
                  (list (format nil "HTTP_PROXY=http://127.0.0.1:~D" port))
                  :timeout 3)))
           (test-assert (zerop (sandbox-result-exit-code result))
                        "proxy-only command completes through the managed bridge")
           (test-assert (string= (sandbox-result-output result) "pong")
                        "managed proxy bridge carries bidirectional bytes"))
      (sb-bsd-sockets:socket-close server)
      (sb-thread:join-thread thread :default nil)))
  nil)

(defun run-tests ()
  "Run all cl-exec-sandbox tests and return true."
  (setf *test-count* 0)
  (test-policy-validation)
  (test-read-only-enforcement)
  (test-workspace-write-enforcement)
  (test-missing-protected-metadata)
  (test-deny-and-nested-override)
  (test-deny-glob)
  (test-unrestricted-filesystem-with-isolated-network)
  (test-external-execution-context)
  (test-timeout)
  (test-isolated-network-seccomp)
  (test-managed-proxy-network)
  (format t "~&~D cl-exec-sandbox tests passed.~%" *test-count*)
  t)
