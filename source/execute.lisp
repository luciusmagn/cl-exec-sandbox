(in-package #:cl-exec-sandbox)

;;;; -- Results --

(defclass sandbox-result ()
  ((exit-code
    :initarg :exit-code
    :reader sandbox-result-exit-code
    :type integer
    :documentation "The process exit status, or a signal-derived implementation status.")
   (output
    :initarg :output
    :reader sandbox-result-output
    :type string
    :documentation "Captured standard output.")
   (error-output
    :initarg :error-output
    :reader sandbox-result-error-output
    :type string
    :documentation "Captured standard error.")
   (timed-out-p
    :initarg :timed-out-p
    :reader sandbox-result-timed-out-p
    :type boolean
    :documentation "Whether supervision terminated the process after its deadline.")
   (real-seconds
    :initarg :real-seconds
    :reader sandbox-result-real-seconds
    :type real
    :documentation "Elapsed monotonic wall-clock seconds."))
  (:documentation "The complete captured outcome of one sandboxed command."))

(defun execute--read-file (path)
  "Return PATH's complete contents, or an empty string when it was not published."
  (if (probe-file path)
      (uiop:read-file-string path)
      ""))

(defun execute--safe-delete (path)
  "Remove transient PATH only when it is still an empty file or directory."
  (when (probe-file path)
    (handler-case
        (if (uiop:directory-pathname-p (probe-file path))
            (uiop:delete-empty-directory path)
            (delete-file path))
      (error ()
        nil)))
  nil)

(defun execute--environment-entry->cons (entry)
  "Convert one KEY=VALUE environment ENTRY to UIOP's portable cons form."
  (let ((separator (position #\= entry)))
    (unless separator
      (error 'sandbox-policy-error
             :message (format nil "Malformed environment entry: ~S" entry)))
    (cons (intern (string-upcase (subseq entry 0 separator)) :keyword)
          (subseq entry (1+ separator)))))

(defun execute--launch-plan (plan input output-path error-path merge-output-p)
  "Launch PLAN with INPUT and redirected output paths."
  (let ((arguments
          (list :input input
                :output output-path
                :error-output (if merge-output-p :output error-path)
                :directory (sandbox-plan-working-directory plan)
                :ignore-error-status t)))
    (when (sandbox-plan-environment-provided-p plan)
      (setf arguments
            (append arguments
                    (list :env
                          (mapcar #'execute--environment-entry->cons
                                  (sandbox-plan-environment plan))))))
    (apply #'uiop:launch-program
           (cons (uiop:native-namestring (sandbox-plan-program plan))
                 (sandbox-plan-arguments plan))
           arguments)))

(defun execute--run-plan (plan input timeout merge-output-p)
  "Run PLAN with INPUT and optional TIMEOUT, returning a SANDBOX-RESULT."
  (uiop:with-temporary-file (:pathname output-path
                             :prefix "cl-exec-sandbox-output-")
    (uiop:with-temporary-file (:pathname error-path
                               :prefix "cl-exec-sandbox-error-")
      (let* ((started (/ (get-internal-real-time)
                         (coerce internal-time-units-per-second 'double-float)))
             (process
               (handler-case
                   (execute--launch-plan plan input output-path error-path
                                         merge-output-p)
                 (error (condition)
                   (error 'sandbox-execution-error
                          :message (format nil "Could not launch sandbox: ~A" condition)
                          :command
                          (cons (uiop:native-namestring
                                 (sandbox-plan-program plan))
                                (sandbox-plan-arguments plan))))))
             (timed-out-p nil))
        (loop while (uiop:process-alive-p process)
              for elapsed = (- (/ (get-internal-real-time)
                                  (coerce internal-time-units-per-second
                                          'double-float))
                               started)
              do (when (and timeout (>= elapsed timeout))
                   (setf timed-out-p t)
                   (uiop:terminate-process process :urgent t)
                   (return))
                 (sleep 0.01))
        (let ((exit-code (uiop:wait-process process))
              (finished (/ (get-internal-real-time)
                           (coerce internal-time-units-per-second 'double-float))))
          (make-instance 'sandbox-result
                         :exit-code exit-code
                         :output (execute--read-file output-path)
                         :error-output (execute--read-file error-path)
                         :timed-out-p timed-out-p
                         :real-seconds (- finished started)))))))

(defun run-sandboxed
    (program arguments
     &key
       policy
       working-directory
       environment
       clear-environment-p
       input
       timeout
       merge-output-p)
  "Run PROGRAM and ARGUMENTS under POLICY and return a captured SANDBOX-RESULT."
  (unless (or (null timeout) (and (realp timeout) (plusp timeout)))
    (error 'sandbox-policy-error
           :message "TIMEOUT must be NIL or a positive number of seconds."))
  (let ((plan (sandbox-build-plan program arguments
                                  :policy policy
                                  :working-directory working-directory
                                  :environment environment
                                  :clear-environment-p clear-environment-p)))
    (unwind-protect
         (execute--run-plan plan input timeout merge-output-p)
      (dolist (path (reverse (sandbox-plan-cleanup-paths plan)))
        (execute--safe-delete path)))))
