"""TcSaveTestUtils.py

"""

import os, sys
import subprocess
import tempfile
import shutil
import logging
import json

DUMMY_IFTYPE = "dummy"

def clearDummyLinks(log=None):
    cmd = ('ip', '-json', 'link', 'show',)
    out = subprocess.check_output(cmd,
                                  universal_newlines=True)
    links = [x['ifname'] for x in json.loads(out)]
    links = [x for x in links if x.startswith('dummy')]
    for link in links:
        cmd = ('ip', 'link', 'del', link,)
        subprocess.check_call(cmd)

def isLinux():
    return 'linux' in sys.platform.lower()

def isRoot():
    return os.getuid() == 0

def isDut():
    return os.path.exists('/etc/onl/platform')

def isVbox():
    try:
        out = subprocess.check_output(('dmidecode', '-s', 'system-manufacturer',),
                                      stderr=subprocess.STDOUT,
                                      universal_newlines=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False
    return 'innotek' in out.lower()

def isKvm():
    try:
        out = subprocess.check_output(('dmidecode', '-s', 'system-manufacturer',),
                                      stderr=subprocess.STDOUT,
                                      universal_newlines=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False
    return 'qemu' in out.lower()

def isVirtual():
    return isVbox() or isKvm()

def isPhysical():

    if not isDut():
        return False
    with open('/etc/onl/platform', 'rt') as fd:
        platform = fd.read()
    platKeys = platform.split('-')
    # arch-vendor-model-model-model-...-r0

    if not os.path.isdir('/sys/firmware/devicetree/base'):
        return False
    if not os.path.exists('/sys/firmware/devicetree/base/model'):
        return False
    with open('/sys/firmware/devicetree/base/model', 'rt') as fd:
        model = fd.read()
    if platKeys[1] in model:
        return True
    if platKeys[2] in model:
        return True
    return False

logger = None

def setUpModule():
    global logger

    logging.basicConfig()
    logger = logging.getLogger("unittest")
    logger.setLevel(logging.DEBUG)

    os.environ['TEST_IFNAME_PREFIX'] = 'dummy'
    # cause the ifname enumeration code to include dummy links

    clearDummyLinks(log=logger)

    # add two dummy links to which qdiscs can be attached
    # here, dummy0 may already be defined
    cmd = ('ip', 'link', 'add', 'dummy0', 'type', DUMMY_IFTYPE,)
    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError:
        pass
    for cmd in (('ip', 'addr', 'add', '10.254.0.1', 'dev', 'dummy0',),
                ('ip', 'link', 'add', 'dummy1', 'type', DUMMY_IFTYPE,),
                ('ip', 'addr', 'add', '10.254.0.2', 'dev', 'dummy1',)):
        subprocess.check_call(cmd)

def tearDownModule():
    clearDummyLinks(log=logger)
    os.environ.pop('TEST_IFNAME_PREFIX', None)

class IptablesTestMixin(object):

    def saveFromLines(self, ruleLines):
        """Generate an abbreviated ruleset.

        Assume the default targets for the root chains (ACCEPT).
        """

        buf = ""
        buf += "*filter\n"

        chains = {}
        chains.setdefault('INPUT', None)
        chains.setdefault('OUTPUT', None)
        chains.setdefault('FORWARD', None)

        for line in ruleLines:
            words = line.split()
            chain = words[1]
            for chain_ in chain.split(','):
                chains.setdefault(chain_, None)
            if words[-2:-1] in [['-j',], ['-g',],]:
                chain_ = words[-1]
                if chain_ not in ('ACCEPT', 'DROP', 'SKIP',
                                  'REJECT',
                                  'LOG',):
                    chains.setdefault(chain_, None)

        dflChains = [x for x in chains.keys() if x in ('INPUT', 'OUTPUT', 'FORWARD',)]
        otherChains = [x for x in chains.keys() if x not in ('INPUT', 'OUTPUT', 'FORWARD',)]

        if 'INPUT' in dflChains:
            buf += ":INPUT ACCEPT [0:]\n"
        if 'OUTPUT' in dflChains:
            buf += ":OUTPUT ACCEPT [0:]\n"
        if 'FORWARD' in dflChains:
            buf += ":FORWARD ACCEPT [0:]\n"

        for chain in sorted(otherChains):
            buf += ":%s - [0:]\n" % chain

        if ruleLines:
            buf += "\n".join(ruleLines) + "\n"

        buf += "COMMIT\n"
        return buf

class ScriptTestMixin(object):

    def setUpWorkdir(self):
        self.workdir = tempfile.mkdtemp(prefix="test-",
                                        suffix=".d")

    def tearDownWorkdir(self):
        workdir, self.workdir = self.workdir, None
        if workdir and os.path.exists(workdir):
            shutil.rmtree(workdir)

    def setUpScripts(self):
        """Create an executable script for the DUT.

        This is because the DUT won't launch scripts generated by BrazilPython.
        XXX rothcar -- need to migrate this to something we can deploy to dentOS.

        XXX rothcar -- make sure these line up with the entry points in setup.py
        """

        bindir = os.path.join(self.workdir, "bin")
        os.mkdir(bindir)

        srcdir = os.path.dirname(__file__)
        pydir = os.path.abspath(os.path.join(srcdir, "../src"))

        # Hurrrr, see
        # https://stackoverflow.com/questions/10813538/shebang-line-limit-in-bash-and-linux-kernel
        pybindir, pybin = None, sys.executable
        if len(pybin) > 127:
            pybindir, pybin = os.path.split(pybin)

        for scriptName, modName in (('iptables-slice', 'SliceApp',),
                                    ('iptables-unroll', 'UnrollApp',),
                                    ('iptables-unslice', 'UnsliceApp',),
                                    ('tc-flower-load', 'LoadApp',),
                                    ('iptables-scoreboard', 'ScoreboardApp',),):
            scriptPath = os.path.join(bindir, scriptName)
            with open(scriptPath, 'wt') as fd:
                if pybindir is not None:
                    fd.write("#!/usr/bin/env %s\n" % pybin)
                else:
                    fd.write("#!%s\n" % pybin)
                fd.write("import sys\n")
                fd.write("sys.path.insert(0, \"%s\")\n" % pydir)
                fd.write("import petunia.%s\n" % modName)
                fd.write("petunia.%s.main()\n" % modName)
            os.chmod(scriptPath, 0o755)

        self.os_environ_PATH = os.environ['PATH']
        if pybindir is not None:
            os.environ['PATH'] = (bindir
                                  + ':' + pybindir
                                  + ':' + os.environ['PATH'])
        else:
            os.environ['PATH'] = (bindir
                                  + ':' + os.environ['PATH'])

    def tearDownScripts(self):
        os.environ['PATH'] = self.os_environ_PATH

class PhysicalTestMixin(object):

    def clearPhysicalInterfaces(self):
        """Initialize the front-panel ports."""

        cmd = ('ip', '-json', 'link', 'show',)
        out = subprocess.check_output(cmd,
                                      universal_newlines=True)
        links = [x['ifname'] for x in json.loads(out)]
        intfs = [x for x in intfs if x.startswith('swp')]

        fno, p = tempfile.mkstemp(prefix="tc-",
                                  suffix=".in")
        with os.fdopen(fno, 'wt') as fd:
            for ifName in intfs:
                fd.write("qdisc del dev %s ingress\n" % ifName)

        cmd = ('tc', '-force', '-batch', p)
        try:
            subprocess.check_call(cmd)
        except subprocess.CalledProcessError:
            pass
        os.unlink(p)