#from Tkinter import Tk, Frame, Menu
#from Tkinter import Checkbutton, BooleanVar
#from Tkinter import BOTH, Listbox, StringVar
#from Tkinter import END, E, W, S, N, Text
##from Tkinter import Button, Label, Style, Text
#from ttk import Label, Style, Button

from Tkinter import *

import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg 
from matplotlib.figure import Figure

import signal
import os
import subprocess
#import psutil
from subprocess import Popen, PIPE, STDOUT
lineNumbers = [0]*1000000
child_pid = None 

def signal_handler(signal, frame):
    print('You pressed Ctrl+C!')

class GUI(Frame):
  
    def __init__(self, parent):
        Frame.__init__(self, parent)   
         
        self.parent = parent        
        self.initUI()
        self.stopFlag = 1
        
        
    def initUI(self):
      
        self.main_container = Frame(self.parent, border=1)
        self.main_container.pack(side='top', fill='both', expand=True)


        self.top_frame = Frame(self.main_container, border=1)
        self.bottom_frame = Frame(self.main_container, border=1)
        self.bottom_left_frame = Frame(self.bottom_frame, border=1)
        self.bottom_right_frame=Frame(self.bottom_frame, border=1)
        self.bottom_right_top_frame = Frame(self.bottom_right_frame, border=1)
        self.bottom_right_bottom_frame = Frame(self.bottom_right_frame, border = 1)
        
        self.top_frame.pack(side='top', fill='x', expand=False)
        self.bottom_frame.pack(side='bottom', fill='both', expand=True)

        self.bottom_left_frame.pack(side='left', fill='y', expand=False)
        self.bottom_right_frame.pack(side='right', fill='y', expand=True)

# change label to text to display info
        #self.main_box = Lable(self.bottom_right_frame, height=20, width=80, background='gray', text='Main Display Window')
        #self.main_box = Text(self.bottom_right_frame, height=20, width=80, background='gray', wrap = 'word')
        self.main_box = Text(self.bottom_right_frame, height=25, width=120, background='gray', wrap = 'word')
        self.main_box.pack(side='top', fill='both', padx=5, pady=5, expand=True)
        self.main_box.bind("<1>", self.on_text_button)

        #self.detail_box = Label(self.bottom_right_frame, height=20, width=50, background='gray', text='Window for detailed info of packet')
        #self.detail_box = Text(self.bottom_right_frame, height=20, width=50, background='gray', wrap = 'word') 
        self.detail_box = Text(self.bottom_right_frame, height=25, width=80, background='gray', wrap = 'word') 
        self.detail_box.pack(side='left', anchor=W, fill='both', padx=5, pady=5)

        #self.graph_box = Label(self.bottom_right_frame, height=20, width=30, background='gray', text='Window for graph')
        #self.graph_box.pack(side='right', anchor=E, fill='both', padx=5, pady=5)

        self.parent.title("Packet Analyzer")
        self.pack(fill = BOTH, expand = True)

        menubar = Menu(self.parent)
        self.parent.config(menu=menubar)
        
        fileMenu = Menu(menubar)
        fileMenu.add_command(label="Exit", command=self.onExit)
        fileMenu.add_command(label="Show", command=self.onShow)
        menubar.add_cascade(label="File", menu=fileMenu)
        
        startbtn = Button(self.top_frame, text="Start",command=self.onStart)
        startbtn.pack(side='left', padx=250, pady=5)
        stopbtn = Button(self.top_frame, text="Stop", command=self.onStop)
        stopbtn.pack(side='left', padx = 20, pady=5)

        lbl = Label(self.bottom_left_frame, text="Protocols")
        lbl.pack(side='top', padx=5, pady=10, anchor=W)
        
        self.varapp1 = BooleanVar() #HTTP
        self.varapp2 = BooleanVar() #DHCP
        self.vartrans1 = BooleanVar() #TCP
        self.vartrans2 = BooleanVar() #UDP
        self.varnet = BooleanVar() #IP
        self.varlink = BooleanVar() #Ethernet2


        self.onShow()

    def onExit(self):
        self.quit()

    def onStart(self):
        print "Update the display"
        # start reading the file have to go to start
        #pid = os.fork()
        #if pid > 0: # parent
        #    self.stopFlag = 0
        #    self.updateDisplay([1, 1, 1, 1, 1, 1]) 
        #else :
        proc = subprocess.Popen(["./analyzer"], shell = False)
        global child_pid
        child_pid = proc.pid
        print child_pid
        print "HERE"
        self.stopFlag = 0
        self.fp = open('protocolDump.txt', 'r')
        self.updateDisplay([1, 1, 1, 1, 1, 1])
        

    def onStop(self):
        self.stopFlag = 1
        global child_pid
        if child_pid is None:
            pass
        else:
            #proc = subprocess.Popen(["sudo", "kill", "-9", "%d" % child_pid])
            #os.system("kill -9 %d" % child_pid)
            print "killed"
            os.kill(child_pid, signal.SIGALRM)
            signal.signal(signal.SIGALRM, signal_handler)
            print "after killed"
            self.fp = open('protocolDump.txt', 'r')
            self.updateDisplay([1, 1, 1, 1, 1, 1])
            #self.kill(child_pid)

    def onShow(self):
        cbx = self.getList()
        i = 1
        for cb in cbx:
            cb.select()
            #cb.grid(row = i, column = 1, columnspan=1, padx=2, pady=2,
            #        sticky=W)
            cb.pack(side='top', padx=5, pady=5, anchor=W)
            i += 1

    def onCheckClick(self):
        flag=[0, 0, 0, 0, 0, 0] #flag to display protocols
        if self.varapp1.get() == True:
            flag[0] = 1
        if self.varapp2.get() == True:
            flag[1] = 1
        if self.vartrans1.get() == True:
            flag[2] = 1
        if self.vartrans2.get() == True:
            flag[3] = 1
        if self.varnet.get() == True:
            flag[4] = 1
        if self.varlink.get() == True:
            flag[5] = 1
        self.updateDisplay(protocols = flag)

    def updateDisplay(self, protocols ):
        self.stopFlag = 0
        print "Update called"
        if self.stopFlag == 1:
            return
        print "here"
        self.fp.seek(0, 0)
        self.detailed = [""]
        protocolCounts = [0, 0, 0, 0, 0, 0]
        lines = self.fp.readlines()
        self.main_box.delete('1.0', 'end')
        #lines = [x.strip() for x in lines] dont remove \n
        mapping = {'HTTP : ': 0, 'DHCP : ':1,
                'TCP  : ': 2, 'UDP  : ':3,
                'IP   : ': 4, 'ETHR : ':5}
        pktNumber = 0

        lineNo = 1
        global lineNumbers

        for line in lines:
            if line[:7] == "#######":
                pktNumber += 1
                if pktNumber != 1:
                    self.main_box.insert('end', "\n")
                    lineNo += 1
                self.main_box.insert('end', "Packet %d\n" % pktNumber)
                self.detailed.append("Packet %d\n" % pktNumber)
                lineNumbers[lineNo] = pktNumber
                lineNo += 1
                continue
            elif len(line) < 3:
                x = 1  # DUMMY SHIZ
            elif line[:7] not in mapping.keys(): # here if detail
                #print line
                #print pktNumber -1, self.detailed
                x = 1 # DUMMY SHIZ
            else : # here if header line
                if protocols[mapping[line[:7]]] == 0:
                    x = 1 # DUMMY SHIZ
                else:
                    protocolCounts[mapping[line[:7]]] += 1
                    #self.detailed.append(line+' -- detailed INfo here bitch')
                    self.main_box.insert('end', line)
                    lineNo += 1
#                    lineNumbers[lineNo] = pktNumber
                    #self.main_box.config(text = line)
                    #self.main_box.update_idletasks()
            self.detailed[pktNumber] += line
            lineNumbers[lineNo] = pktNumber

        #print lineNumbers[:10]
        #print self.detailed[1]
        print "Update display from flags : \nUpdating Graph", protocols
        self.updateGraph(protocolCounts)

    def updateGraph(self, protocolCounts):
        if hasattr(self, 'plot_widget'):
            self.plot_widget.destroy()
        totPkts = sum(protocolCounts)
        if totPkts == 0:
            return
        # swap sizes
        protocolCounts[0], protocolCounts[5] = protocolCounts[5], protocolCounts[0]
        protocolCounts[1], protocolCounts[4] = protocolCounts[4], protocolCounts[1]
        protocolCounts[2], protocolCounts[3] = protocolCounts[3], protocolCounts[2]
        protocolCounts[0] = protocolCounts[0]*100.0/totPkts;
        protocolCounts[1] = protocolCounts[1]*100.0/totPkts;
        protocolCounts[2] = protocolCounts[2]*100.0/totPkts;
        protocolCounts[3] = protocolCounts[3]*100.0/totPkts;
        protocolCounts[4] = protocolCounts[4]*100.0/totPkts;
        protocolCounts[5] = protocolCounts[5]*100.0/totPkts;
        explode = (0, 0, 0, 0, 0, 0)
        
        labels = ['Ethernet %1.2f%%' % protocolCounts[0], 
                'IP %1.2f%%' % protocolCounts[1], 
                'UDP %1.2f%%' % protocolCounts[2], 
                'TCP %1.2f%%' % protocolCounts[3], 
                'DHCP %1.2f%%' % protocolCounts[4], 
                'HTTP %1.2f%%' % protocolCounts[5]]

        #fig = Figure(figsize=(20,30), dpi=None, frameon=self.bottom_right_frame)
        ###fig = Figure(figsize=(20, 30), dpi = 100)
        ###ax1 = fig.add_subplot(111)


        colours = ['yellowgreen', 'gold', 'lightskyblue', 'lightcoral', 'orange', 'red']

        fig = plt.figure(1, figsize=(30, 30))
        fig.clear()
        #fig = plt.figure(figsize=(20, 30))
        plt.ion()
        #fig1, ax1 = plt.subplots()
        plt.pie(protocolCounts, 
                explode = explode, 
                colors = colours,
                #autopct='%1.2f%%',
                shadow = False, 
                startangle = 90)
        plt.legend(labels, loc=(-0.05, 0.05), prop={'size':8})
        plt.axis('equal') # Equal aspect ratio. Pie as circle

        canvas = FigureCanvasTkAgg(fig, self.bottom_right_frame)
        self.plot_widget = canvas.get_tk_widget()
        self.plot_widget.heigh = 20
        self.plot_widget.width = 30
        self.plot_widget.pack(side='right', anchor=E)#, fill='both')
        fig.canvas.draw()
        ###canvas.show()
        ###canvas.get_tk_widget().pack(side='bottom', fill='both', expand=True)
        #canvas.get_tk_widget().pack(side='right', anchor = E, fill='both', expand=True)
        print "Graph Displayed"
        #self.graph_box = Label(self.bottom_right_frame, height=20, width=30, background='gray', text='Window for graph')
        #self.graph_box.pack(side='right', anchor=E, fill='both', padx=5, pady=5)

        #plt.show()

    def on_text_button(self, event):
        index = self.main_box.index("@%s,%s" % (event.x, event.y))
        line, char = index.split(".")
        #print index, line, char
        global lineNumbers
        pktNumber = lineNumbers[int(line)]
        detailedText = self.detailed[pktNumber] # 0 based indexing 
        self.detail_box.delete('1.0', 'end')
        self.detail_box.insert('end', detailedText)

    def getList(self):
        cb_app1 = Checkbutton(self.bottom_left_frame, text="HTTP", 
                variable = self.varapp1, command=self.onCheckClick)
        cb_app2 = Checkbutton(self.bottom_left_frame, text="DHCP",
                variable = self.varapp2, command=self.onCheckClick)
        cb_trans1 = Checkbutton(self.bottom_left_frame, text="TCP", 
                variable = self.vartrans1, command=self.onCheckClick)
        cb_trans2 = Checkbutton(self.bottom_left_frame, text="UDP",
                variable = self.vartrans2, command=self.onCheckClick)
        cb_net = Checkbutton(self.bottom_left_frame, text="IP", 
                variable = self.varnet, command=self.onCheckClick)
        cb_link = Checkbutton(self.bottom_left_frame, text="Ethernet2",
                variable = self.varlink, command=self.onCheckClick)
        cbx = [cb_app1, cb_app2, cb_trans1, cb_trans2, cb_net,
                cb_link]
        return cbx

def main():
    root = Tk()
    #root.geometry("768x512+200+150")
    root.geometry("1024x768+50+50")
    root.title('Packet Analyzer')
    app = GUI(root)
    root.mainloop()  


if __name__ == '__main__':
    main()
