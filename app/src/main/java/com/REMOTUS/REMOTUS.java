
package com.REMOTUS;

import android.app.Activity;
import android.widget.TextView;
import android.os.Bundle;
import android.os.SystemClock;


public class REMOTUS extends Activity
{
	private class ERRORCODE
	{
		public static final int SUCCESS = 0;
		public static final int SOCKET_FAIL = 1;
		public static final int REUSEADDR_FAIL = 2;
		public static final int SNDTIMEO_FAIL = 3;
		public static final int BIND_FAIL = 4;

		public static final int RECV_FAIL = 5;
		public static final int RCVTIMEO_FAIL = 6;
		public static final int LOGIN_FAIL = 7;
		public static final int PROTOCOL_FAIL = 8;
		public static final int PROCESSORTYPE_FAIL = 9;
		public static final int SHELLCODE_FAIL = 10;
		public static final int SEND_FAIL = 11;
		public static final int CALL_FAIL = 12;
		public static final int HANDLE_FAIL = 13;
		public static final int ACCESS_FAIL = 14;
		public static final int MODULE_FAIL = 15;
		public static final int PATTERN_FAIL = 16;
		public static final int PROCESS_FAIL = 19;
	}
	public static final String[] ERRORSTRINGS = {
		"SUCCESS",
		"SOCKET_FAIL",
		"REUSEADDR_FAIL",
		"SNDTIMEO_FAIL",
		"BIND_FAIL",
		"RECV_FAIL",
		"RCVTIMEO_FAIL",
		"LOGIN_FAIL",
		"PROTOCOL_FAIL",
		"PROCESSORTYPE_FAIL",
		"SHELLCODE_FAIL",
		"SEND_FAIL",
		"CALL_FAIL",
		"HANDLE_FAIL",
		"ACCESS_FAIL",
		"MODULE_FAIL",
		"PATTERN_FAIL",
		"RESULT_FAIL",
		"SHELLCODERECV_FAIL",
		"PROCESS_FAIL",
		"TESTFAIL"
	};


	private native int Init();
	private native int Listen();
	private native int Attach();
	private native int Setup();
	private native int Run();
	private native int Free();
	private native int Exit();

	static {
		System.loadLibrary("RemoteApiAndroid");
	}


	private class STATUS
	{
		public static final int IDLE = 0;
		public static final int INIT = 1;
		public static final int INIT_FAIL = 2;
		public static final int LISTEN = 3;
		public static final int LISTEN_FAIL = 4;
		public static final int ATTACH = 5;
		public static final int ATTACH_FAIL = 6;
		public static final int SETUP = 7;
		public static final int SETUP_FAIL = 8;
		public static final int RUN = 9;
		public static final int RUN_FAIL = 10;
		public static final int STOPPED = 11;
	}

	class Control {
		public volatile boolean Restart = false;
		public volatile int Status = STATUS.IDLE;
		public volatile int Errorcode = ERRORCODE.SUCCESS;
		public volatile TextView tv;
	}

	final Control control = new Control();


	class Worker implements Runnable {
		public void singlerun() {

			control.Status = STATUS.INIT;
			int result = Init();
			if (result != ERRORCODE.SUCCESS) {
				control.Status = STATUS.INIT_FAIL;
				control.Errorcode = result;
				return;
			}

			int exitstatus;
			exit: do {

				control.Status = STATUS.LISTEN;
				result = Listen();
				if (result != ERRORCODE.SUCCESS) {
					Free();
					control.Status = STATUS.LISTEN_FAIL;
					control.Errorcode = result;
					return;
				}

				control.Status = STATUS.ATTACH;
				while (true) {
					if (control.Restart) {
						exitstatus = STATUS.STOPPED;
						break exit;
					}

					result = Attach();
					if (result != ERRORCODE.SUCCESS) {
						if (result == ERRORCODE.PROCESS_FAIL) {
							SystemClock.sleep(5000);
							continue;
						}

						exitstatus = STATUS.ATTACH_FAIL;
						break exit;
					}
					break;
				}

				if (control.Restart) {
					exitstatus = STATUS.STOPPED;
					break exit;
				}

				control.Status = STATUS.SETUP;
				result = Setup();
				if (result != ERRORCODE.SUCCESS) {
					exitstatus = STATUS.SETUP_FAIL;
					break exit;
				}


				long runstarttime = System.nanoTime();

				control.Status = STATUS.RUN;
				while (true) {
					if (control.Restart) {
						exitstatus = STATUS.STOPPED;
						break exit;
					}
					
					result = Run();

					if (result != ERRORCODE.SUCCESS) {
						exitstatus = STATUS.RUN_FAIL;
						break;
					}

					long runendtime = System.nanoTime();

					if(runstarttime + 1000000 > runendtime)
					{
						SystemClock.sleep(1);
						runstarttime = runendtime + 1000000;
					}
					else
					{
						runstarttime = runendtime;
					}
				}

			} while (false);

			Exit();
			control.Status = exitstatus;
			control.Errorcode = result;
		}

		@Override
		public void run() {

			singlerun();

			while (true) {
				if (control.Restart) {
					control.Restart = false;
					singlerun();
				} else {
					SystemClock.sleep(200);
				}
			}

		}
	}

	class UiHandler implements Runnable {

		private String geterror() {
			int errorcode = control.Errorcode;

			if(errorcode < 0 || errorcode >= ERRORSTRINGS.length)
				return Integer.toString(errorcode);

			return ERRORSTRINGS[errorcode];
		}

		@Override
		public void run() {

			while (true) {

				runOnUiThread(new Runnable() {
					@Override
					public void run() {

						String status;

						switch (control.Status) {
						case STATUS.INIT:
							status = "Initializing";
							break;
						case STATUS.INIT_FAIL:
							status = "Initialization failed - " + geterror();
							break;
						case STATUS.LISTEN:
							status = "Waiting for client";
							break;
						case STATUS.LISTEN_FAIL:
							status = "Connection error - " + geterror();
							break;
						case STATUS.ATTACH:
							status = "Waiting for target process";
							break;
						case STATUS.ATTACH_FAIL:
							status = "Couldn't attach to target - " + geterror();
							break;
						case STATUS.SETUP:
							status = "Scanning target process";
							break;
						case STATUS.SETUP_FAIL:
							status = "Invalid target process - " + geterror();
							break;
						case STATUS.RUN:
							status = "Running...";
							break;
						case STATUS.RUN_FAIL:
							status = "Error - " + geterror();
							break;

						default:
							status = "???";
						}

						control.tv.setText(status);

					}
				});

				SystemClock.sleep(200);
			}

		}
	}

	/** Called when the activity is first created. */
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		control.tv = new TextView(this);
		control.tv.setText("Loading");
		setContentView(control.tv);

		Worker worker = new Worker();
		UiHandler uihandler = new UiHandler();

		new Thread(worker).start();
		new Thread(uihandler).start();
	}
}
