# -*- coding:utf-8 -*-

import idc
import idaapi
import ida_nalt
import ida_idd
import ida_dbg
import ida_kernwin

import os.path
import time
	
from PyQt5 import QtGui, QtCore, QtWidgets
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *

PLUGNAME = "Ida2pwntools"


class MainCallable(object):
	def __init__(self, handler):
		self.handler = handler
	def __call__(self):
		return self.handler()


class WaitThread(QThread):
	sinOut = pyqtSignal(str)  
	sinOutEnd = pyqtSignal(str)
  
	def __init__(self, parent=None):
		super(WaitThread,self).__init__(parent)
		self.filename = ida_nalt.get_root_filename()
		self.target_pid = -1

	def run(self):  
		self.prepare_debug()
		self.sinOutEnd.emit("start debug (PID: %d)" % self.target_pid)
		
	def prepare_debug(self):
		def get_processes_list():
			self.pis = ida_idd.procinfo_vec_t()
			ida_dbg.get_processes(self.pis)
			return 1

		c = 0
		found_pid = False
		while not found_pid:
			c = (c+1) % 5
			self.sinOut.emit("finding process: [%s]" % self.filename+('.' * c).ljust(5, " "))

			ida_kernwin.execute_sync(MainCallable(get_processes_list), \
				ida_kernwin.MFF_FAST)

			for proc in self.pis:
				print proc.name
				proc_name = proc.name.split(" ")[1]
				idx = proc_name.rfind("/")

				if idx != -1:
					proc_name = proc_name[idx+1:]
				
				if self.filename == proc_name:
					self.target_pid = proc.pid
					found_pid = True
					break

			if not found_pid:
				self.sleep(1)


class WaitDialog(QDialog):
	def __init__(self):
		super(WaitDialog,self).__init__()
		self.initUI()
		self.thread = WaitThread()
		self.thread.sinOut.connect(self.outText)
		self.thread.sinOutEnd.connect(self.start_debug)
		
	def outText(self, text):
		self.l2.setText(text)
		
	def close_debug(self):
		self.thread.terminate()
		self.hide()

	def get_target_pid(self):
		return self.thread.target_pid
	
	def start_debug(self, text):
		idaapi.msg("[%s] %s\n" % (PLUGNAME, text))
		self.hide()

	def initUI(self):
		self.setWindowTitle(PLUGNAME)
		self.setGeometry(400,400,300,260)
		self.setFixedWidth(320)
		self.setFixedHeight(240)
		vbox = QVBoxLayout()
		
		self.l2 = QLabel()
		self.l2.setAlignment(Qt.AlignCenter)
		vbox.addWidget(self.l2)
		
		self.closeButton = QPushButton()
		self.closeButton.setText("Stop Waiting")
		self.closeButton.setShortcut('Ctrl+D')
		self.closeButton.clicked.connect(self.close_debug)
		self.closeButton.setToolTip("Stop Waiting")
		self.closeButton.resize(200,100)
		vbox.addWidget(self.closeButton)
		
		self.setLayout(vbox)


def prepare_debug_noui():
	target_pid = -1
	idaapi.msg("[%s] waiting...\n" % (PLUGNAME))
	
	filename = ida_nalt.get_root_filename()
	pis = ida_idd.procinfo_vec_t()
	ida_dbg.get_processes(pis)

	for proc in pis:
		proc_name = proc.name.split(" ")[1]
		idx = proc_name.rfind("/")

		if idx != -1:
			proc_name = proc_name[idx+1:]

		if filename == proc_name:
			target_pid = proc.pid
			break
	
	if target_pid != -1:
		idaapi.msg("[%s] start debug (PID: %d)\n" % (PLUGNAME, target_pid))
		ida_dbg.attach_process(target_pid, -1)
		idc.GetDebuggerEvent(idc.WFNE_SUSP, -1)
		ida_dbg.continue_process()
	else:
		idaapi.msg("[%s] exit waiting\n" % (PLUGNAME))


class IDA_Pwntools_Plugin_t(idaapi.plugin_t):
	comment = ""
	help = "help"
	wanted_name = PLUGNAME
	wanted_hotkey = "f12"
	flags = idaapi.PLUGIN_KEEP
	
	def prepare_debug_ui(self):
		wd = WaitDialog()
		idaapi.msg("[%s] waiting...\n" % (PLUGNAME))
		wd.thread.start()
		wd.exec_()

		target_pid = wd.get_target_pid()
		if target_pid != -1:
			ida_dbg.attach_process(target_pid,-1)
			idc.GetDebuggerEvent(idc.WFNE_SUSP, -1)
			ida_dbg.continue_process()
		else:
			idaapi.msg("[%s] exit waiting\n" % (PLUGNAME))

	def init(self):
		menu_bar = next(i for i in QtWidgets.qApp.allWidgets() if isinstance(i, QtWidgets.QMenuBar))
		menu = menu_bar.addMenu(PLUGNAME)
		menu.addAction("Connect to pwntools").triggered.connect(self.prepare_debug_ui)
		return idaapi.PLUGIN_KEEP

	def term(self):
		idaapi.msg("[%s] terminated" % (PLUGNAME))
	
	def run(self, arg):
		prepare_debug_noui()


def PLUGIN_ENTRY():
	return IDA_Pwntools_Plugin_t()

