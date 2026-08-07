(in-package #:cl-exec-sandbox)

;;;; -- Host Path Helpers --

(defun path--components (path)
  "Return PATH's non-empty slash-separated components."
  (remove-if (lambda (component) (zerop (length component)))
             (uiop:split-string (uiop:native-namestring path)
                                :separator '(#\/))))

(defun path--under-p (path root)
  "Return true when absolute PATH is ROOT or a descendant of ROOT."
  (let ((path-namestring (uiop:native-namestring path))
        (root-namestring
          (uiop:native-namestring (uiop:ensure-directory-pathname root))))
    (or (string= path-namestring
                 (string-right-trim "/" root-namestring))
        (uiop:string-prefix-p root-namestring path-namestring))))

(defun path--absolute (path cwd)
  "Resolve PATH against CWD without requiring it to exist."
  (uiop:ensure-absolute-pathname (pathname path) cwd))

(defun path--safe-relative-subpath (subpath)
  "Return SUBPATH as a relative pathname or signal a policy error."
  (let ((pathname (pathname subpath)))
    (when (or (uiop:absolute-pathname-p pathname)
              (member :up (pathname-directory pathname)))
      (error 'sandbox-policy-error
             :message (format nil "Workspace subpath must stay relative: ~A" subpath)))
    pathname))

(defun path--executable-file-p (path)
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

(defun path--directories ()
  "Return PATH entries as absolute directory pathnames."
  (loop for entry in (uiop:split-string (or (uiop:getenv "PATH") "")
                                        :separator '(#\:))
        when (plusp (length entry))
          collect (uiop:ensure-directory-pathname
                   (uiop:ensure-absolute-pathname entry (uiop:getcwd)))))
