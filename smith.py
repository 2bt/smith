#!/usr/bin/python3.6
import asyncio
import signal
import html
import sys
import json
import os
import time
import traceback
from PyQt5.QtWidgets import *
import PyQt5.QtGui as QtGui
from quamash import QEventLoop
if sys.platform == "win32":
	import colorama
	colorama.init()


LOG_FILE_NAME = "log.txt"
WINDOW_WIDTH = 1000
WINDOW_HEIGHT = 800
FONT_SIZE = 10


def to_json(o):
	return json.dumps(o)

def to_pretty_json(o):
	return json.dumps(o, indent=2, sort_keys=True)

def from_json(s):
	return json.loads(s)


class LogWin(QPlainTextEdit):
	def __init__(self, app):
		QPlainTextEdit.__init__(self)
		self.app = app
		self.setReadOnly(True)
		self.setUndoRedoEnabled(False)
		font = QtGui.QFont("Monospace", FONT_SIZE)
		self.setFont(font)
		self.setLineWrapMode(0)
		self.setMaximumBlockCount(1000)
		self.file = open(LOG_FILE_NAME, "w")

#		bg_color = "#ddd"
#		self.setStyleSheet("background-color:" + bg_color);
#		self.normal_format = QtGui.QTextBlockFormat()
#		self.normal_format.setBackground(QtGui.QColor(bg_color))
#		self.error_format = QtGui.QTextBlockFormat()
#		self.error_format.setBackground(QtGui.QColor("#faa"))
#		self.miner_format = QtGui.QTextBlockFormat()
#		self.miner_format.setBackground(QtGui.QColor("#ffc"))
#		self.debug_format = QtGui.QTextBlockFormat()
#		self.debug_format.setBackground(QtGui.QColor("#aaf"))


	def miner_log(self, text):
		for line in text.rstrip().split("\n"):
#			self.appendHtml("<pre style='color:#333'>%s</pre>" % html.escape(line))
			self.appendHtml("<pre style='color:#880'>%s</pre>" % html.escape(line))
			self.file.write("[miner]%s\n" % line)
			print("\033[33m[miner]\033[m" + line)
		self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())
#		cursor = self.textCursor()
#		cursor.setBlockFormat(self.miner_format)


	def log(self, text):
		for line in text.rstrip().split("\n"):
			self.appendHtml("<pre>%s</pre>" % html.escape(line))
			self.file.write(line + "\n")
			print(line)
		self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())
#		cursor = self.textCursor()
#		cursor.setBlockFormat(self.normal_format)


	def log_error(self, text):
		for line in text.rstrip().split("\n"):
			self.appendHtml("<pre style='color:#f00'>error: %s</pre>" % html.escape(line))
			self.file.write("error: %s\n" % line)
			print("\033[31merror:\033[m "+ line)
		self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())
#		cursor = self.textCursor()
#		cursor.setBlockFormat(self.error_format)

	def log_debug(self, text):
		for line in text.rstrip().split("\n"):
			self.appendHtml("<pre style='color:#00f'>debug: %s</pre>" % html.escape(line))
			self.file.write("debug: %s\n" % line)
			print("\033[34mdebug:\033[m "+ line)
		self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())
#		cursor = self.textCursor()
#		cursor.setBlockFormat(self.debug_format)



class MainWin(QWidget):
	def __init__(self, app):
		QWidget.__init__(self)
		self.app = app
		self.log_win = LogWin(app)

		self.button_hbox = None
		self.buttons = []

		self.vbox = QVBoxLayout()
		self.vbox.addWidget(self.log_win)

		self.resize(WINDOW_WIDTH, WINDOW_HEIGHT)
		self.setWindowTitle("Smith")
		self.setLayout(self.vbox)
		self.show()


	def remove_buttons(self):
		if self.button_hbox:
			self.vbox.removeItem(self.button_hbox)
			self.button_hbox = None
			for b in self.buttons: b.setParent(None)
			self.buttons = []


	def add_buttons(self, button_desc):
		self.remove_buttons()
		self.button_hbox = QHBoxLayout()
		for label, data in button_desc:
			b = QPushButton(label)
			def on_clicked_factory(label, data):
				def on_clicked():
					if app.proc:
						self.log_win.log("send %r to miner process." % data)
						app.proc.stdin.write(data.encode())
					else:
						self.log_win.log_error("miner process not running.")
				return on_clicked
			b.clicked.connect(on_clicked_factory(label, data))
			self.button_hbox.addWidget(b)
			self.buttons.append(b)
		self.button_hbox.addStretch(1)
		self.vbox.addLayout(self.button_hbox)


	def closeEvent(self, event):
		event.ignore()
		app.close()


class App:
	# helper method for thread creation
	# catches exceptions and logs trace
	def create_task(self, coro):
		def done_callback(future):
			try: future.result()
			except:
				self.log_debug(traceback.format_exc())
		task = self.loop.create_task(coro)
		task.add_done_callback(done_callback)
		return task


	def __init__(self, loop):
		self.exiting = False
		self.loop = loop
		self.proc = None
		self.algo = None
		self.prev_algo = None

		self.server = None
		self.miner_writer = None
		self.miner_state = "off"
		self.miner_exit_time = 0

		# gui and loggin methods
		self.main_win = MainWin(self)
		self.log       = self.main_win.log_win.log
		self.miner_log = self.main_win.log_win.miner_log
		self.log_error = self.main_win.log_win.log_error
		self.log_debug = self.main_win.log_win.log_debug

		# signal
		if sys.platform == "linux2":
			def on_sigint():
				self.log("received signal SIGINT.")
				self.close()
			self.loop.add_signal_handler(signal.SIGINT, on_sigint)

		# pool
		self.pool_writer = None
		self.pool_task = None

		# load config
		self.load_config()
		if not self.config: return

		self.pool_task = self.create_task(self.pool_coro())

		# nice for debugging
#		async def input_coro():
#			while True:
#				line = await loop.run_in_executor(None, sys.stdin.readline)
#				line = line.strip()
#				if line == "k":
#					self.proc.kill()
#		self.input_task = self.create_task(input_coro())


	def load_config(self):
		self.log("reading config...")
		self.config = None
		try:
			filename = "config.txt"
			with open(filename) as f: data = f.read()
		except:
			self.log_error("cannot open config file %r." % filename)
			return
		try:
			import ast
			config = ast.literal_eval(data)
		except SyntaxError as e:
			self.log_error("cannot parse config file %r: %s (line %d)." % (filename, e.msg, e.lineno))
			return

		# assure validity of config structure
		try:
			assert type(config) == dict
			check = {
				"local-port": int,
				"pool-addr": str,
				"pool-port": int,
				"login": str,
				"pass": str,
				"miner-restart-delay": (int, float),
				"algos": dict,
			}
			for k, t in check.items():
				assert k in config, "missing key %r" % k
				assert isinstance(config[k], t), "type mismatch"
		except AssertionError as e:
			self.log_error("invalid config structure: %s." % e)
			return
		try:
			for k, v in config["algos"].items():
				assert isinstance(k, str)
				assert isinstance(v, dict)
				for k in ["cmd", "cwd"]:
					assert k in v
					assert isinstance(v[k], str)
		except AssertionError as e:
			self.log_error("invalid config structure.")
			return

		self.config = config
		self.log("config read.")


	def run(self):
		try:
			self.loop.run_forever()
			self.loop.close()
		except:
			self.log_debug(traceback.format_exc())

		# close log file
		self.log("bye.")
		self.main_win.log_win.file.close()


	def close(self):
		async def terminate_coro():
			try:
				if self.pool_writer: self.pool_writer.close()
				if self.pool_task: await self.pool_task
				await self.stop_miner_coro()
				self.loop.stop()
			except:
				self.log_debug(traceback.format_exc())
				self.loop.stop()
		if self.exiting:
			a = QMessageBox.question(self.main_win, "Message", "Force exit?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
			if a == QMessageBox.Yes:
				if self.proc: self.proc.kill()
				self.loop.stop()
			return
		self.log("exiting...")
		self.exiting = True
		self.create_task(terminate_coro())


	async def pool_coro(self):
		pool_addr = self.config["pool-addr"]
		pool_port = self.config["pool-port"]

		self.log("connecting to pool %s..." % str((pool_addr, pool_port)))
		try:
			reader, writer = await asyncio.open_connection(pool_addr, pool_port)
		except Exception as e:
			self.log_error("cannot connect to pool: %s." % e.strerror)
			return

		self.log("connected to pool.")
		self.pool_writer = writer

		if self.exiting:
			# close writer so this whole task will be done fast and we can exit.
			self.pool_writer.close()

		if self.algo == None:
			self.log("sending fake login to pool:")
			login = {
				"id": 1,
				"method": "login",
				"params": {
					"agent": "smith/0.0.1",
					"login": self.config["login"],
					"pass": self.config["pass"],
				}
			}
			self.log(to_pretty_json(login))
			writer.write((to_json(login) + "\n").encode())
		else:
			# start server and run miner
			assert self.proc == None
			assert self.miner_writer == None
			assert self.server == None
			self.server_task = self.create_task(self.run_server_coro())

		while True:
			line = await reader.readline()
			if not line: break
			line = line.decode(errors="ignore")
			o = from_json(line)
			self.log("pool says:")
			self.log(to_pretty_json(o))

			# find algorithm
			algo = None
			if "result" in o and "job" in o["result"] and "algo" in o["result"]["job"]:
				algo = o["result"]["job"]["algo"]
				del o["result"]["job"]["algo"]
			elif o.get("method") == "job" and "algo" in o["params"]:
				algo = o["params"]["algo"]
				del o["params"]["algo"]

			if algo and algo != self.algo:
				self.prev_algo = self.algo
				self.algo = algo
				self.log("algorithm has changed from %s to %s." % (self.prev_algo, self.algo))
				if self.algo not in self.config["algos"]:
					self.log("algorithm is not supported.")
					await self.stop_miner_coro()
					continue
				else:
					self.log("algorithm is supported.")
					break


			# pass data to to miner
			if self.miner_writer:
				self.miner_writer.write((to_json(o) + "\n").encode())

		self.log("disconnected from pool.")
		writer.close()

		# restart
		if not self.exiting:
			await self.stop_miner_coro()
			self.pool_task = self.create_task(self.pool_coro())


	async def run_server_coro(self):
		async def on_connected(reader, writer):
			addr = writer.get_extra_info('peername')
			self.log("miner connected %s." % str(addr))
			self.server.close()

			self.miner_writer = writer
			while True:
				line = await reader.readline()
				if not line: break
				line = line.decode(errors="ignore")
				o = from_json(line)
				self.log("miner says:")
				self.log(to_pretty_json(o))

				# fix login and pass
				if o.get("method") == "login":
					o["params"]["login"] = self.config["login"]
					o["params"]["pass"] = self.config["pass"]

				# pass data to pool
				self.pool_writer.write((to_json(o) + "\n").encode())

			if self.miner_state in ("stopping", "off") :
				self.log("miner disconnected.")
			else:
				self.log_error("miner disconnected unexpectedly.")
			writer.close()
			self.miner_writer = None

		local_addr = "127.0.0.1"
		local_port = self.config["local-port"]
		self.log("listening for miner to connect %s..." % str((local_addr, local_port)))
		self.server = await asyncio.start_server(on_connected, local_addr, local_port, backlog=1)

		self.miner_task = self.create_task(self.run_miner_coro())

		try:
			await self.server.wait_closed()
			self.server = None
		except:
			self.log_debug(traceback.format_exc())


	async def run_miner_coro(self):
		if self.exiting: return
		assert self.algo in self.config["algos"]
		assert self.miner_state == "off"

		# sleep before restart
		pause = time.time() - self.miner_exit_time
		delay = max(0, self.config["miner-restart-delay"] - pause)
		if delay:
			self.log("sleeping before miner restart...")
			await asyncio.sleep(delay)
			if self.exiting: return
			self.log("sleeping done.")

		algo_config = self.config["algos"][self.algo]
		args = algo_config["cmd"].split()

		self.log("starting miner process...")
		try:
			DETACHED_PROCESS = 0x00000008
			self.proc = await asyncio.create_subprocess_exec(
				*args,
				cwd=algo_config["cwd"],
				stdin=asyncio.subprocess.PIPE,
				stdout=asyncio.subprocess.PIPE,
				stderr=asyncio.subprocess.PIPE,
				creationflags=DETACHED_PROCESS)
		except FileNotFoundError as e:
			self.log_error("cannot start miner process: %s." % e.strerror)
			if self.server:
				self.server.close()
				self.server = None
			return
		except:
			self.log_debug(traceback.format_exc())
			return

		self.log("miner process running.")
		self.miner_state = "on"
		self.main_win.add_buttons(algo_config.get("buttons", []))
		while True:
			line = await self.proc.stdout.readline()
			if not line: break
			line = line.decode(errors="ignore")
			self.miner_log(line.rstrip())

		await self.proc.wait()
		if self.miner_state == "stopping":
			self.log("miner process stopped (%d)." % self.proc.returncode)
		else:
			self.log_error("miner process stopped unexpectedly (%d)." % self.proc.returncode)
			# close pool to toggle restart
			self.pool_writer.close()
		self.miner_state = "off"
		self.proc = None
		self.miner_exit_time = time.time()
		self.main_win.remove_buttons()

		# close connection and server
		if self.server:
			self.server.close()
			self.server = None
		if self.miner_writer:
			self.miner_writer.close()
			self.miner_writer = None
		await self.server_task


	async def stop_miner_coro(self):
		if self.proc and not self.proc.returncode:
			assert self.miner_state == "on"
			self.miner_state = "stopping"
			self.log("stopping miner process...")

			# TODO: how do we stop the miner process?

			#self.proc.send_signal(signal.SIGINT)
			#self.miner_writer.write("q".encode())

			# process shuts itself done nicely on disconnect
			if self.miner_writer:
				self.miner_writer.close()
			else:
				self.proc.kill()

			await self.miner_task


if __name__ == "__main__":
	qt = QApplication(sys.argv)
	loop = QEventLoop(qt)
	loop.set_debug(True)
	asyncio.set_event_loop(loop)
	app = App(loop)
	app.run()
