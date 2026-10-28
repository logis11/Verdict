import sys
sys.path.insert(0,'/home/kinn/projects/Huntail')
from huntail import tools
tools.set_target(binary='/home/kinn/projects/Huntail/work/bin/srvnet-9444.sys')
def dec(t): print(tools._t_decompile({'target':t}))
def ff(p,l=40): print(tools._t_find_funcs({'pattern':p,'limit':l}))
def cl(t): print(tools._t_callers({'target':t}))
def ce(t): print(tools._t_callees({'target':t}))
def cp(s,d,m=8): print(tools._t_callpath({'src':s,'dst':d,'maxdepth':m}))
