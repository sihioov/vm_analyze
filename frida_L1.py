import os, frida, time

exe = r"D:\black\L2j0m.exe"
cwd = os.path.dirname(exe)

# 현재 파이썬 파일이 있는 폴더
mydir = os.path.dirname(os.path.abspath(__file__))
agent_path = os.path.join(mydir, "frida_L2.js")   # 같은 폴더의 JS

dev  = frida.get_local_device()
pid  = dev.spawn(exe, cwd=cwd)
sess = dev.attach(pid)

dev.resume(pid)
time.sleep(2)

script = sess.create_script(open(agent_path, encoding="utf-8").read())
script.load()
