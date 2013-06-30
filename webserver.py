#!/usr/bin/python
#Copyright Neil LoBracco 2005

import os,sys,socket,string,re,mimetypes,stat,base64,crypt,time,threading,select
from getopt import *
from stat import *

def log(s):
	doLog = False
	doLog= True
	if (logfile):
		writer=open(logfile,'a')
	else:
		writer=sys.stdout
	if doLog:
		writer.write(str(s)+'\n')
		writer.flush()
def setGETOrPOST(array,ls):
	log("got %s in set..." % ls)
	for g in string.split(ls,"&"):
		ge=string.split(g,"=")
		if len(ge)==1: #set to nothing
			ge.append('')
		array[ge[0]]=ge[1] #0 is the name, 1 is the value
def getPHPPage(f,get,post): #damn, this is an ugly hack
	dn=os.path.dirname(f)
	tmpfilename="%s/.__tmp.php" % dn
	tmp = open(tmpfilename, 'w')
	tmp.write("<?php\n")
	log( "get: %s post: %s" % (get,post))
	tmp.write(arrayAsPHP(get,"_GET"))
	tmp.write(arrayAsPHP(post,"_POST"))
	tmp.write("?>\n")
	tmp.write(open(f,'r').read()) #somebody should make php bindings for python
	tmp.flush()
	tmp.close()
	php_pipe = os.popen("php %s" % tmpfilename)
	#os.remove(tmpfilename)
	return php_pipe.read()
def arrayAsPHP(arr,arrayName):
	str=''
	for n in arr.keys():
		v=re.sub('\+',' ',arr[n])
		str+='$%s[\"%s\"]= \"%s\";\n' % (arrayName,n,v) #generates phpness
	return str
def isProtected(filename,dir): #if its directory, somewhere, has a .htaccess file
	if(filename[0] == '/'):
		filename=filename[1:]
	toSearch=string.split(filename,"/")
	if not dir:
		toSearch=toSearch[:-1]
	for i in range(1,len(toSearch)):
		toSearch[i]=toSearch[i-1]+'/'+toSearch[i]
	for fts in toSearch:
		fts="%s/%s"%(doc_root,fts)
		log("validating directory: %s" %fts)
		if '.htaccess' in os.listdir(fts):
			return True
	return False
def isAuthorized(filename,ws):
	if '.htaccess' in filename.split('/'):
		return False
	provided=False
	for line in ws:
		tokens=string.split(line," ")
		if tokens[0]=='Authorization:' and tokens[1]=='Basic':
			b64 = tokens[2]
			provided=True
			break
	if not provided:
		log("no auth provided")
		return False
	decoded=base64.decodestring(b64) # string is given as base64
	up=string.split(decoded,":")
	user,passw=up
	log ( "user: %s \n pass: %s" %(user,passw))
	global pwdfile
	p=open(pwdfile,'r')
	log( "opened %s" % pwdfile)
	authed=False
	line=p.readline()
	while(line):
		line=line[:-1] #strip off newline
		unpw=line.split(":")
		if unpw[0]!=user: #username doesn't match, try next row
			log("not user: %s" % unpw[0])
		else:
			log("read from file: user %s" % user)
			pwenc=unpw[1]
			log("pwenc read: %s" % pwenc)
			crypted=crypt.crypt(passw,pwenc[:2])
			if pwenc==crypted:
				authed=True
				log("%s: user %s getting protected file %s" % (time.asctime(time.localtime(time.time())),user,filename))
			else :
				log("login error for %s: crypted: %s but pwdfile says %s" % (user,crypted,pwenc))
			break
		line=p.readline()
	return authed

class RequestHandlerThread(threading.Thread):
	def __init__(self,t=None):
		if t:
			self.cs,self.addr=t
		self.GET={}
		self.POST={}
		threading.Thread.__init__(self)
	def setStuff(self,t):
		self.cs,self.addr=t
	def run(self):
		RECV_QUANTA=1024
		try:
			a=self.cs.recv(RECV_QUANTA)
			while (len(a) % RECV_QUANTA == 0) and len(a):
				a+=self.cs.recv(RECV_QUANTA)
		except:
			return
		self.wholething=a.splitlines() #split into lines
		self.rq=self.wholething[0].split(" ") #tokens on first line
		try:
			self.actuallyDoTheWork()
		except Exception,e:
			log(e)
		self.cs.close()
	def actuallyDoTheWork(self):
		type=self.rq[0] #GET,POST,etc
		doc = self.rq[1] #what document to get
		cn=self.cs
		for ln in self.wholething: #Obtain Host: line
			tks = ln.split(" ")
			if tks[0]=="Host:":
				hostname=tks[1]
		doc=string.split(doc,"?")
		if len(doc)!=1: #GET options supplied
			setGETOrPOST(self.GET,doc[1])
		doc=doc[0]
		if  type != "GET" and type!="POST":
			self.sendCode(501) #We can't handle that
			return
		if type=="POST":
			poststring=''
			next=False
			for s in self.wholething: #search for line after blank line: that has the POST options
				if not s:
					next=True
					continue
				if next:
					poststring=s
					break
			setGETOrPOST(self.POST,poststring)
		log("\n\nNew request starts here!");
		log(self.wholething)
		log("GET: %s\nPOST:%s" %(self.GET,self.POST))
		if (doc == '/'):
			doc='/index.html' #standard behavior
		tmp=doc.find('%')
		while tmp!=-1: #convert %dd to characters in GET
			old=doc[tmp:tmp+3]
			doc=re.sub(old,chr(int(old[1:],16)),doc)
			tmp=doc.find('%',tmp+1)
		for p in self.POST.keys(): #and in POST
			v=self.POST[p]
			tmp=v.find('%')
			while tmp!=-1:
				old=v[tmp:tmp+3]
				v=re.sub(old,chr(int(old[1:],16)),v)
				tmp=v.find('%',tmp+1)
			self.POST[p]=v
		filename = doc_root + doc
		log("trying to service %s" % filename)
		if (not os.path.exists(filename)):
			self.sendCode(404)
			return
		isDir=os.path.isdir(filename)
		if (isProtected(doc,isDir)):
			if (not isAuthorized(filename,self.wholething)):
				self.sendCode(401)
				cn.send("WWW-Authenticate: Basic realm=\"private stuff\"\n")
				msg="<html><head><title>Unauthorized</title></head><body><h1>You are not authorized to view %s</h1></body></html>" % doc
				self.sendStuff(msg)
				log("pwned unauthorized access on: %s" % filename)
				return
		if (isDir):
			log("is directory")
			msg='<html><head><title>Contents of directory %s</title></head><body><h2>This is the contents of %s</h2><br><br>' % (doc,doc)
			ctype="text/html"
			list=os.listdir(filename)
			filename=re.sub(doc_root,"",filename)#strip out doc_root
			try:
				list.remove('.htaccess') #especially private
			except:
				pass
			msg+="<a href=\"%s\">Parent Directory</a><br>\n" % os.path.split(filename.rstrip('/'))[0]
			prefix = "http://" + hostname # the Host: line of the request
			filename = prefix+filename
			for file in list:
				fullpath=re.sub(" ",r"%20",filename+"/"+file)
				msg+="<a href=\"%s\">" % fullpath 
				log("fullpath: %s" % fullpath)
				msg+=file+"</a><br>\n"
			msg+="</body></html>"
			log("msg: %s" % msg)
			self.sendCode(200)
			self.sendStuff(msg)
		elif (filename[-4:]==".php"): #ends with .php: try and parse this kid
			self.sendCode(200)
			msg=getPHPPage(filename,self.GET,self.POST)
			self.sendStuff(msg)
		else: #just give them their little file, but do it in parts in case it's big, like a movie
			self.sendCode(200)
			ctype=mimetypes.guess_type(filename)[0]
			if not ctype: ctype="text/plain"
			cn.send("Content-Type: %s\n" % ctype)
			cn.send("Content-Length: %s\n\n" % os.stat(filename)[ST_SIZE])
			READ_QUANTA=100000
			f=open(filename,'r')
			msg=f.read(READ_QUANTA)
			cn.send(msg)
			while (((len(msg) % READ_QUANTA) == 0) and (len(msg) !=0)):#still more
				msg=f.read(READ_QUANTA)
				cn.send(msg)
	def sendCode(self,code):
		num=int(code)
		cdstring="HTTP/1.0 " + str(code) + " "
		if num==200:
			cdstring+="OK"
		elif num==404:
			cdstring+="Not Found"
		elif num==401:
			cdstring+="Unauthorized"
		elif num==501:
			cdstring+="Not Implemented"
		cdstring+='\n'
		self.cs.send(cdstring)
	def sendStuff(self,msg,ctype="text/html"):
		self.cs.send("Content-Type: %s\n" % ctype)
		self.cs.send("Content-length: %d\n\n" % len(msg))
		self.cs.send(msg)


def usage():
	print "Usage: %s <options> document_root\
	\nOptions: \
	\n-p port : Set the port number to listen on.  Default is 80.\
	\n-f pwdfile : Use pwdfile to look up passwords.  Default is /var/www/.htpasswd\
	\n-l logfile : Log to logfile, rather than the standard output.\
	\n-d : Fork off and become a daemon\
	"% sys.argv[0]
	sys.exit(1)

port=80
pwdfile="/var/www/.htpasswd"
temp_dir='/tmp' #where we create temporary php files
logfile=None
daemonize=False
try:
	args,stuff=gnu_getopt(sys.argv[1:],"p:f:l:d")
except GetoptError,msg:
	print msg
	usage()
	sys.exit(1)
try:
	for option,value in args:
		if(option=='-p'):
			port=int(value)
		elif(option=='-f'):
			pwdfile=value
		elif option=='-l':
			logfile=value
		elif option=='-d':
			daemonize=True
except:
	usage()
	sys.exit(1)
if len(stuff) != 1: #no doc_root
	usage()
	sys.exit(1)
if (daemonize and not logfile):
	print ("If -d is used, I've gotta have a logfile to write to (via -l)")
	sys.exit(1)
doc_root=stuff[0]
if daemonize:
	if os.fork() > 0:
		sys.exit(0)
	doc_root=os.getcwd() + '/' +  doc_root
	os.chdir('/')
	os.setsid()
	os.umask(0)
	dpid=os.fork()
	if dpid > 0:
		log("Daemon PID: %d" % dpid)
		sys.exit()
MAX_POOL_SIZE=5 #Max number of pooled handler threads
INITIAL_POOL_SIZE=1 
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.bind(('',port)) #allow connections from anywhere
s.settimeout(1) #wake up every second
s.listen(5)
rhtpool=[]
for n in range(INITIAL_POOL_SIZE): #fill it up
	rhtpool.append(RequestHandlerThread())
while 1:
	try:		
		t=s.accept()
		if len(rhtpool)==0: #empty, create a new one on the fly
			rht=RequestHandlerThread(t)
		else:
			rht=rhtpool.pop(0)
			rht.setStuff(t)
		rht.start()
		if not s in select.select([s],[],[],0)[0]: #isn't one waiting
			raise socket.timeout #replace the one we used
	except socket.timeout:
		if(len(rhtpool) < MAX_POOL_SIZE):
			rhtpool.append(RequestHandlerThread())
	except Exception,e:
		log(e)
		continue
