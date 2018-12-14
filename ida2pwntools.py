# -*- coding:utf-8 -*-
import os.path
import time
	
from PyQt5 import QtGui, QtCore, QtWidgets
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *


PLUGNAME = "Ida2pwntools"

class MyThread(QThread):  
  
	sinOut = pyqtSignal(str)  
	sinOutEnd = pyqtSignal(str)
  
	def __init__(self,parent=None):  
		super(MyThread,self).__init__(parent)  
  
		self.identity = None  
  
	def setIdentity(self,text):  
		self.identity = text  
  
	def setVal(self,val):  
		self.times = int(val)  

	def run(self):  
		# while self.times > 0 and self.identity:  
			# ##发射信号  
			# self.sinOut.emit(self.identity+" "+str(self.times))  
			# self.times -= 1
			# time.sleep(1)
		self.prepare_debug()
		self.sinOutEnd.emit('start debug')
		
	def prepare_debug(self):
		c = 0
		global target_id
		#目标pid
		target_id = -1
		
		found_pid = False
		while not found_pid:
			
			#获取程序名称
			filename = ida_nalt.get_input_file_path()
			#or use ida_nalt.get_root_filename()
			
			#查找是否有该名称的进程
			c = (c + 1)%5
			self.sinOut.emit('finding process: [%s]'%filename+('.'*c).ljust(5," "))

			#获取当前进程列表
			pis = ida_idd.procinfo_vec_t()
			cnt = ida_dbg.get_processes(pis)
			for i in range(cnt):
				proc = pis[i]
				proc_name = proc.name.split(" ")[1]
				idx = proc_name.rfind("/")
				if idx!=-1:
					proc_name = proc_name[idx+1:]
				
				if filename == proc_name:
					target_id = proc.pid
					found_pid = True #跳出大循环
					break

			if not found_pid:
				self.sleep(1)


				
class PushButton(QDialog):
	def __init__(self):
		super(PushButton,self).__init__()
		self.initUI()
		
		self.thread = MyThread()  
		# self.thread.setIdentity("thread1")  
		# self.thread.setVal(5)
		self.thread.sinOut.connect(self.outText)
		self.thread.sinOutEnd.connect(self.start_debug)
		
		##执行线程的run方法
		
	
	def outText(self,text):  
		self.l2.setText(text)
		
	def close_debug(self):
		self.thread.terminate()
		self.hide()
	
	def start_debug(self,text):
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
		self.closeButton.setText("Stop Waiting")		  #text
		self.closeButton.setShortcut('Ctrl+D')  #shortcut key
		self.closeButton.clicked.connect(self.close_debug)
		self.closeButton.setToolTip("Stop Waiting") #Tool tip
		self.closeButton.resize(200,100)
		vbox.addWidget(self.closeButton)
		
		self.setLayout(vbox)

def prepare_debug_ui():
	global ex
	global target_id
	target_id = -1
		
	idaapi.msg("[%s] waiting...\n" % (PLUGNAME))
	ex.thread.start()
	ex.exec_()
	
	
	#开始调试
	if (target_id != -1):
		idaapi.msg("[%s] start debug\n" % (PLUGNAME))
		ida_dbg.attach_process(target_id,-1)
		GetDebuggerEvent(WFNE_SUSP, -1)
		#继续调试
		ida_dbg.continue_process()
	else:
		idaapi.msg("[%s] exit waiting\n" % (PLUGNAME))
		
class IDA_Pwntools_Plugin_t(idaapi.plugin_t):
	comment = ""
	help = "help"
	wanted_name = PLUGNAME
	wanted_hotkey = "f12"
	flags = idaapi.PLUGIN_KEEP
	
	def load_configuration(self):
		pass

	def init(self):
		menu_bar = next(i for i in QtWidgets.qApp.allWidgets() if isinstance(i, QtWidgets.QMenuBar))
		menu = menu_bar.addMenu(PLUGNAME)
		menu.addAction("Connect to pwntools").triggered.connect(prepare_debug_ui)
	

	def term(self):
		idaapi.msg("[%s] terminated" % (PLUGNAME))
	
	def run(self, arg):
		pass
				
# register IDA plugin
def PLUGIN_ENTRY():
	return IDA_Pwntools_Plugin_t()

ex = PushButton()
target_id = -1
