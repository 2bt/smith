#!/usr/bin/python
import pyuv
import socket
import signal
import json
import sys
import os


#pool_addr = socket.gethostbyname("my.host.name")
pool_addr  = "78.46.85.142"
pool_port  = 35349
local_port = 55555


def to_json(o):
	return json.dumps(o)

def to_pretty_json(o):
	return json.dumps(o, indent=2, sort_keys=True)

def from_json(s):
	return json.loads(s)


class App:
	SUPPORTED_ALGOS = {
		"monero_v7",
		"heavy",
	}


	def miner_log(self, msg):
		for line in msg.split("\n"):
			print "\033[35m[miner]\033[m" + line


	def log(self, msg):
		for line in msg.split("\n"):
			print "\033[33m[proxy]\033[m" + line


	def run(self, algo=None):
		self.loop = pyuv.Loop.default_loop()

		# catch signals
		self.sig = pyuv.Signal(self.loop)
		self.sig.start(self.on_signal, signal.SIGINT)

		# listen in stdin
		self.stdin = pyuv.Pipe(self.loop)
		self.stdin.open(sys.stdin.fileno())
		self.stdin.start_read(self.on_input)

		self.algo       = None
		self.proc       = None
		self.proc_state = "off"
		self.miner      = None
		self.listener   = None

		self.connect_to_pool()

		# enter main loop
		self.loop.run()


	def connect_to_pool(self):
		self.log("connecting to pool")
		self.pool = pyuv.TCP(self.loop)
		self.pool.connect((pool_addr, pool_port), self.on_pool_connected)


	def on_pool_connected(self, tcp, error):
		self.log("connected to pool")
		self.pool.start_read(self.on_pool_read)
		if self.algo == None:
			login = {
				"id": 1,
				"method": "login",
				"params": {
					"agent": "smith/0.0.1",
					"login": "rig",
					"pass": "x",
				}
			}
			self.log("sending fake login to pool:")
			self.log(to_pretty_json(login))
			self.pool.write(to_json(login))

		else:
			self.start_miner_process()


	def start_miner_process(self):
		assert self.proc == None
		if self.algo in self.SUPPORTED_ALGOS:
			self.log("start miner process")
			cwd = os.path.join(os.getcwd(), "miners", self.algo)
			self.stdin  = pyuv.Pipe(self.loop, True)
			self.stdout = pyuv.Pipe(self.loop, True)

			self.proc = pyuv.Process.spawn(
				self.loop,
				args = [os.path.join(cwd, "xmr-stak")],
				cwd = cwd,
				flags = pyuv.UV_PROCESS_WINDOWS_HIDE,
				stdio = [
					pyuv.StdIO(stream=self.stdin,  flags=pyuv.UV_CREATE_PIPE | pyuv.UV_READABLE_PIPE),
					pyuv.StdIO(stream=self.stdout, flags=pyuv.UV_CREATE_PIPE | pyuv.UV_WRITABLE_PIPE),
					#pyuv.StdIO(fd=2, flags=pyuv.UV_INHERIT_FD)
					pyuv.StdIO(flags=pyuv.UV_IGNORE)
				],
				exit_callback=self.on_miner_process_exited)
			self.proc_state = "running"
			self.stdout.start_read(self.on_miner_process_output)

			# init listener
			self.listener = pyuv.TCP(self.loop)
			self.listener.bind(("127.0.0.1", local_port))
			self.listener.listen(self.on_miner_connected, 1)


	def handle_action(self):
		action = self.action
		self.action = None
		if action == "exit":
			self.loop.stop()
		elif action == "reconnect":
			self.connect_to_pool()


	def stop_miner_process(self, action=None):
		self.action = action
		if self.proc:
			if self.proc_state == "running":
				self.log("stopping miner process")
				self.proc.kill(2)
				self.proc_state = "stopping"
		else:
			self.handle_action()


	def on_miner_process_exited(self, proc, status, sig):
		self.log("miner process stopped")
		self.proc.close()
		self.stdin.close()
		self.stdout.close()
		self.proc = None
		self.proc_state = "off"
		self.handle_action()


	def on_miner_connected(self, tcp, error):
		self.log("miner connected")
		self.miner = pyuv.TCP(self.loop)
		self.listener.accept(self.miner)
		self.listener.close()
		self.listener = None
		self.miner.start_read(self.on_miner_read)


	def on_miner_read(self, tcp, data, error):
		if not data:
			self.miner.close()
			self.miner = None
			if self.proc_state == "stopping":
				self.log("miner disconnected")
			elif self.proc_state == "running":
				self.log("miner disconnected unexpectedly")
				self.log("disconnect from pool")
				self.pool.close()
				self.pool = None
				self.stop_miner_process("reconnect")
			else:
				assert False
			return

		self.log("miner says:")
		for line in data.split("\n"):
			if not line: continue
			self.log(line)
			o = from_json(line)
			self.log(to_pretty_json(o))

		# pass data on to pool
		if self.pool:
			self.pool.write(data)


	def on_pool_read(self, tcp, data, error):
		if not data:
			self.log("disconnected from pool :(")
			self.pool.close()
			self.pool = None
			return

		self.log("pool says:")
		algo = None
		for line in data.split("\n"):
			if not line: continue
			self.log(line)
			o = from_json(line)
			self.log(to_pretty_json(o))
			if "result" in o and "job" in o["result"]:
				algo = o["result"]["job"].get("algo")
			elif "method" in o and o["method"] == "job":
				algo = o["params"].get("algo")

		if algo and algo != self.algo:
			self.log("algorithm has changed from %s to %s" % (self.algo, algo))
			self.algo = algo
			if self.algo not in self.SUPPORTED_ALGOS:
				self.log("algorithm is not supported")
				self.stop_miner_process()
			else:
				self.log("algorithm is supported")
				if self.pool:
					self.log("disconnect from pool")
					self.pool.close()
					self.pool = None
				self.stop_miner_process("reconnect")
			return

		if self.miner: self.miner.write(data)


	def on_miner_process_output(self, pipe, data, error):
		if not data: return
		self.miner_log(data.strip())


	def on_input(self, pipe, data, error):
		cmd = data.strip()
		if self.proc:
			# pass command to miner process
			self.stdin.write(cmd)


	def on_signal(self, handle, signum):
		self.log("exiting")
		self.sig.close()

		if self.pool:
			self.pool.close()
			self.pool = None
		if self.miner:
			self.miner.close()
			self.miner = None
		if self.listener:
			self.listener.close()
			self.listener = None

		self.stop_miner_process("exit")


if __name__ == "__main__":
	App().run()
