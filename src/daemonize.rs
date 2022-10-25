use std::ffi::CString;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::os::unix::prelude::OwnedFd;
use std::os::unix::prelude::FromRawFd;

/** enum DaemonInitCompleter
 *
 * @brief Used in a daemonized child to indicate that the
 * child has completed initialization and the parent can
 * now exit.
 *
 * @desc Any non-trivial daemon has to perform non-trivial
 * initialization, such as reading configuration, setting
 * up ports, etc. any of which might fail.
 * When designing such a daemon, we should really make
 * sure everything is set up correctly before the parent
 * exits, and if there is an error the parent should fail.
 *
 * If this object is dropped before its `completed` function
 * is invoked, this will be considered an error in the child,
 * and cause `daemonize` on the parent to fail.
 * Only if the `completed` function is called on the completer
 * object will the parent `daemonize` return with an `Ok`
 * result.
 *
 * Once the daemon has properly initialized, it should call
 * `completed` on this object.
 * This will let the parent `daemonize` return, and also
 * redirect stdout, stderr, and stdin of the daemon to
 * `/dev/null`.
 *
 * Before initialization is marked as completed, the daemon
 * can still write messages to stdout/stderr and get data
 * from stdin.
 * If it encounters an error while initializing, it should
 * exit, panic, or terminate abnormally, which will have the
 * same effect as dropping this object and force an error
 * on the parent.
 */
pub(crate) enum DaemonInitCompleter {
	Completer(OwnedFd)
}

impl DaemonInitCompleter {
	pub(crate) fn completed(self: Self) -> () {
		match self {
			DaemonInitCompleter::Completer(fd) => {
				File::from(fd).write_all(b"\0").unwrap();
				unsafe {
					let path = CString::new("/dev/null").unwrap();
					let i_devnull = libc::open(path.as_ptr(), libc::O_RDONLY);
					if i_devnull >= 0 {
						/* TODO: handle EINTR.  */
						let _ = libc::dup2(i_devnull, 0);
						let _ = libc::close(i_devnull);
					}
					let o_devnull = libc::open(path.as_ptr(), libc::O_WRONLY);
					if o_devnull >= 0 {
						let _ = libc::dup2(o_devnull, 1);
						let _ = libc::dup2(o_devnull, 2);
						let _ = libc::close(o_devnull);
					}
				}
			}
		}
	}
}

/** fn pipe
 *
 * @brief opens a UNIX pipe.
 */
fn pipe() -> (OwnedFd, OwnedFd) {
	let mut fds = std::mem::MaybeUninit::<[libc::c_int; 2]>::uninit();

	let res = unsafe { libc::pipe(fds.as_mut_ptr() as *mut libc::c_int) };
	if res < 0 {
		panic!("daemonize: Cannot open pipe.");
	}

	let out = unsafe { OwnedFd::from_raw_fd(fds.assume_init()[0]) };
	let inp = unsafe { OwnedFd::from_raw_fd(fds.assume_init()[1]) };

	return (out, inp);
}

/** fn daemonize
 *
 * @brief Launch a daemonized process and run the given child
 * function in it.
 *
 * @desc Unlike typical crate implementations of daemonization,
 * this function will wait for the daemon to complete
 * initialization before letting the parent exit.
 *
 * It is strongly recommended that your `main` function only
 * contain an invocation of this and nothing else.
 * Put any important initialization stuff in the `child`
 * function, and make sure to invoke `.completed()` on the
 * completer object once initialization has successfully
 * completed.
 *
 * The actual daemon process will never see this function
 * return; it will normally exit with 0.
 */
pub(crate) fn daemonize<F: FnOnce(DaemonInitCompleter) -> ()>(
		child: F
) -> Result<(), std::io::Error>{
	let (out, inp) = pipe();

	let forkres = unsafe { libc::fork() };
	if forkres < 0 {
		panic!("daemonize: Cannot fork.");
	}
	match forkres {
		0 => {
			std::mem::drop(out);
			let setsidres = unsafe { libc::setsid() };
			if setsidres < 0 {
				panic!("daemonize: Failed to setsid.");
			}

			let fork2res = unsafe { libc::fork() };
			if fork2res < 0 {
				panic!("daemonize: Cannot fork again.");
			}
			match fork2res {
				0 => {
					let completer = DaemonInitCompleter::Completer(inp);
					child(completer);
				}
				_ => { std::mem::drop(inp); }
			}
			std::process::exit(0);
		}
		_ => {
			std::mem::drop(inp);
			/* Wait for child to notify.  If the pipe closes
			 * before we get the notification, then it means
			 * the child died unexpectedly.  */
			let mut buff = Vec::new();
			let mut out = File::from(out);
			match out.read_to_end(&mut buff)? {
				0 => {
					Err(std::io::Error::new(std::io::ErrorKind::Other,
								"daemonize: child did not notify init completion"))
				}
				_ => {
					Ok(())
				}
			}
		}
	}
}
