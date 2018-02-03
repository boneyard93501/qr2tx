#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
    process qr image to extract signed eth transaction
    process eth trasnaction and make it web accesiisble
    add ability to nickname (to:) account

    persistence of passwd and acct nickname courtesy of pickle


    todo:
        1) re-write the qr decoder and bcrypt hashing anc checking in rust and FFI into this app
        2) re-write the app entirely in rust using the parity toolchain and maybe rocket.

    v 0.0.1, 02-02-2018
'''
import os, sys
import pickle as pickle
from string import Template
from copy import deepcopy
from collections import namedtuple

import rlp
import bcrypt
import cherrypy
import requests
from PIL import Image
from web3 import Web3
from pyzbar.pyzbar import decode

SRC_DIR = os.path.abspath(os.path.dirname(sys.argv[0]))
USER_DIR = os.path.abspath(os.path.join(SRC_DIR,'..','users'))
STATIC_DIR = os.path.abspath(os.path.join(SRC_DIR,'..','static'))
SESSION_DIR = os.path.abspath(os.path.join(SRC_DIR,'..','sessions'))
LOG_DIR = os.path.abspath(os.path.join(SRC_DIR,'..','logs'))
HTML_DIR = os.path.abspath(os.path.join(SRC_DIR,'..','html'))
DATA_DIR = os.path.abspath(os.path.join(SRC_DIR,'..','data'))

FAV_PATH = os.path.join(STATIC_DIR,'favicon','favicon.ico')
DEFAULT_HTML_PATH = os.path.join(HTML_DIR,'qr2tx.html')
LOGIN_HTML_PATH = os.path.join(HTML_DIR,'login.html')
QR_PATH = os.path.join(DATA_DIR,'example_qr.png')
DEFAULT_USER_PATH = os.path.join(USER_DIR,'bossman.pickle')


LOG_ROUNDS = 15
MAX_UPLOAD_SIZE = 1024 * 1024
TX_KEYS = [('nonce','toHex',None),
           ('gasprice','toInt','wei'),
           ('startgas','toInt','wei'),
           ('to','toHex',None),
           ('value','toInt','wei'),
           ('data','toText',None),
           ('v','toHex',None),
           ('r','toHex',None),
           ('s','toHex',None)
           ]

ETHEREUM_TIKCER_URL = 'https://api.coinmarketcap.com/v1/ticker/ethereum/'

# need it in global scope becuase of pickle. rather annoying.
Ethview = namedtuple('Ethview','key,value,unit')


# ==================================================================================================================== #
def crypt_pwd(raw_pwd,logrounds=LOG_ROUNDS):
    '''
        wrapper so i don't have to look it up

        : raw_pwd   byte string
        return hased pwd
    '''
    if not isinstance(raw_pwd,bytes):
        raw_pwd = raw_pwd.encode()
    return bcrypt.hashpw(raw_pwd,bcrypt.gensalt(logrounds))


def check_pwd(passwd,hashed):
    '''
        wrapper so i don't have to look it up

        : passwd            user passwd, byte string
        : hashed pwd
        : return bool
    '''
    if not isinstance(passwd,bytes):
        passwd = passwd.encode()
    return bcrypt.checkpw(passwd,hashed)


def pload(fpath):
    '''
        simple pickle load wrapper
        : fpath
        : return dict
    '''
    with open(fpath,'rb') as fd:
        return pickle.load(fd)


def pdump(data,fpath):
    '''
        simple pickle dumo wrapper
        : data dict
        : fpath
        : return bool
    '''
    with open(fpath,'wb') as fd:
        pickle.dump(data,fd)
    return True


def eth_ticker(url=None):
    if url is None:
        url = 'https://api.coinmarketcap.com/v1/ticker/ethereum/'
    r = requests.get(url)
    if r.status_code==200:
        return round(float(r.json()[0]['price_usd']),3)
    return False


# ==================================================================================================================== #
def authinator(fn):
    '''
        : fn
        : return fn obj or raise redirect
    '''
    def _checker(*args,**kwargs):
        '''
            : args
            : kwargs
            return fn or raise redirect
        '''
        if cherrypy.session.get('uname') is None:
            raise cherrypy.Redirect('/')
        return fn(*args,**kwargs)
    return _checker


def login(uname,passwd):
    '''
        : uname
        : passwd
        : return  bool, dict
    '''
    if uname is None or passwd is None:
        msg = 'incomplete credentials'
        return False, {"app-code":400, 'err-msg':msg}

    u_path = os.path.join(USER_DIR,f'{uname}.pickle')
    if not os.path.exists(u_path):
        msg = f'invalid {u_path}. create user.'
        return False, {"app-code":404, 'err-msg':msg}

    with open(u_path,'rb') as fd:
        udata = pickle.load(fd)

    if not isinstance(passwd,bytes):
        passwd = passwd.encode()

    if not bcrypt.checkpw(passwd,udata['passwd']):
        msg = 'invalid password.'
        return False, {"app-code":400, 'err-msg':msg}

    return True, udata


class Root:
    def __init__(self):
        pass

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def jlogin(self):
        jdoc = cherrypy.request.json
        state, data = login(jdoc.get('uname'),jdoc.get('passwd'))
        if not state:
            return data

        cherrypy.session['uname'] = data['uname']
        cherrypy.session['data'] = data

        return {'app-code':200,'data':[]}

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def acctsettr(self):
        jdoc = cherrypy.request.json
        nname = jdoc.get('acct-name')

        # if not nname:
        #    return {"app-code":400,'err_msg':'empty nickname'}
        # not now but we'll revist
        # if len(nname) < 2:
        #    msg = f'nick name must be at least two chars, {nname} is invalid.'
        #    return {"app-code":400,'err-msg':msg}

        if len(nname) > 50:
            msg = f'account name must be at most 50 characters, {nname} is invalid.'
            return {"app-code":400,'err-msg':msg}

        udata = pload(DEFAULT_USER_PATH)
        udata['acct-name'] = f'{nname}'
        pdump(udata,DEFAULT_USER_PATH)

        return {"app-code":200,'data':f'{nname} added'}

    @cherrypy.expose
    def index(self):
        uname = cherrypy.session.get('uname')
        if uname is None:
            with open(LOGIN_HTML_PATH,'r') as fd:
                html = fd.read()

            html = Template(html).safe_substitute(LOGINURL="/txviewer/jlogin")
            return html

        with open(DEFAULT_HTML_PATH,'r') as fd:
            html = fd.read()

        with open(os.path.join(USER_DIR,'bossman.pickle'),'rb') as fd:
            udata = pickle.load(fd)
        tx_view_rows = tx_row_maker(udata['raw-eth-view'],udata.get('acct-name'))
        qr_str = qr_str_formatter(udata['qr-str'])

        html = Template(html).safe_substitute(LOGINURL="/txviewer/jlogin",
                                              ACCTSETTRURL="/txviewer/acctsettr",
                                              TXVIEWCOLS=tx_view_rows,
                                              QRSTR=qr_str
                                              )
        return html


# ==================================================================================================================== #
def get_qr_str(qr_path):
    '''
        we'll just od it at startup, not that we need to with only one code.
        if we add QR upload funcitonality to the web app , here it is.

        NOTE: OS X: brew install zbar; Ubuntu: sudo apt-get install libzbar0

        : qr_path
        : return state <string from qr, err msg>
    '''
    if not os.path.exists(qr_path):
        return False, f'invalid qr path: {qr_path}'

    with Image.open(qr_path) as fd:
        qr_str = decode(fd)[0][0]
        return True, qr_str


def process_hex_str(hex_str):
    '''
        : hex_str       should be a byte string but if not, we convert it an int
        : returns state, results mapped into a list of namedtuples
    '''
    if not isinstance(hex_str,bytes):
        hex_str = int(hex_str,16)

    eth_bs = Web3.toBytes(int(hex_str,16))
    eth_txs = rlp.decode(eth_bs)

    # got to move it into global scope
    # Ethview = namedtuple('Ethview','key,value,unit')

    results = []
    for tx in zip(TX_KEYS,eth_txs):
        if tx[1]:
            results.append(Ethview(tx[0][0],getattr(Web3,tx[0][1])(tx[1]),tx[0][2]))
        else:
            results.append(Ethview(tx[0][0],None,None))

    return True, results


def qr_str_formatter(qr_str,n_delim=80):
    s = ''
    for i in range(0, len(qr_str), n_delim):
        s += (qr_str[i:i + n_delim]).decode() + '<br>'

    s.rstrip('<br>')
    return s


def tx_row_maker(tx_data,acct_nick_name):
    row = '<div class="row mt-1 mb-1" id="{}">{}</div>'

    col = '<div class="col-md-4 offset-md-1"><b>{}</b></div>'
    col +='<div class="col-md-5">{}<span>&nbsp;{}</span></div>'

    inp = '&nbsp;&nbsp;<input type="text" placeholder="account nickname" id="acct-name-id" value="{}"'
    inp +=' name="acct-name" style="border: 0;box-shadow:none;font-size:80%;"><div id="acct-setter-err"'
    inp +=' style="font-size:80%;color:red;"></div>'

    s = ''
    for nt in tx_data:
        i_str = ''
        e_str = ''
        eth_usd = eth_ticker()
        if nt.key.lower()=='to':
            i_str = inp.format(acct_nick_name or '')
        if nt.key.lower() in ['startgas', 'value']:
            eth = Web3.fromWei(nt.value,'ether')
            usd = 'NA'
            if eth_usd:
                __ = round(eth_usd * float(eth),10)
                usd = f'USD:&nbsp;{__:.10f}'
            e_str = f'<span style="font-size:85%;">&nbsp;&nbsp;(ETH &nbsp;{eth:.16f},&nbsp;{usd})</span>'
            print(nt.key,eth,e_str)
        c = col.format(nt.key + i_str,nt.value or '',(nt.unit or '') + e_str)
        r = row.format(f'{nt.key}-result-row',c)
        s += r

    if eth_usd:
        eu_row = f'<div class="row mt-2 mb-1 justify-content-center"'
        eu_row +=f' id="eth-usd-row"><b>ETH-USD: {eth_usd:.3f}</b>&nbsp;'
        eu_row +=f'<i><small><a href="https://coinmarketcap.com/currencies/ethereum/"'
        eu_row +=f' target="_blank">coinmarketcap.com</a></small</i></div>'
        s += eu_row
    return s


# ==================================================================================================================== #
def pidder():
    '''
        make sure we only got one instance running

        :return pid_path (or kills the app)
    '''
    pid = os.getpid()
    pid_path = sys.argv[0].strip('.py') + '.pid'
    if os.path.exists(pid_path):
        with open(pid_path,'r') as fd:
            old_pid = int(fd.read().strip())
            try:
                os.kill(old_pid,0)
                msg = f'app with pid {old_pid} still running ... kill it,'
                msg += ' restart an instance on a different port, or leave it.\n'
                sys.stderr.write(msg)
                sys.exit(1)
            except ProcessLookupError:
                pass
    with open(pid_path,'w') as fd:
        fd.write(f'{pid}\n')
    return pid_path


def cp_setup():
    '''
        : return cp app and server config
    '''
    conf = {'/': {'tools.staticdir.on': True,
                  'tools.staticdir.dir': STATIC_DIR,
                  'tools.sessions.on': True,
                  'tools.sessions.storage_class': cherrypy.lib.sessions.FileSession,
                  'tools.sessions.storage_path': SESSION_DIR,
                  'tools.sessions.timeout': 10,
                  },

            'png':{'tools.staticdir.on': True,
                   'tools.staticdir.dir': os.path.join(STATIC_DIR,'images'),
                   },
            'favicon.ico': {'tools.staticfile.on': True,
                            'tools.staticfile.filename': FAV_PATH
                            }
            }
    server_config = {
        'global': {
            'server.socket_host': '127.0.0.1',
            'server.socket_port': 8080,
            # 'server.socket_host': '0.0.0.0',
            # 'server.socket_port': 61443,
            'server.thread_pool': 20,
            'server.socket_timeout': 60,
            # 'cherrypy.server.ssl_module': 'builtin',
            # 'server.ssl_certificate': '/etc/letsencrypt/live/much.morecowbell.io/fullchain.pem'
            # 'server.ssl_private_key': '/etc/letsencrypt/live/much.morecowbell.io/privkey.pem'
            'log.error_file': os.path.join(LOG_DIR,'cp_error.log'),
            'log.access_file': os.path.join(LOG_DIR,'cp_access.log'),
            # 'environment': 'production',
            'log.screen': True,
            'tools.encode.on': True,
            'tools.encode.encoding': 'utf8',
            'tools.proxy.on': True,
            }
        }

    return conf, server_config


def housekeeping():
    '''
        process the qr png and update the pickle object so we don't have to keep
        coming to the well

        : return state, <eth_view, err-msg>
    '''
    state, qr_str = get_qr_str(QR_PATH)
    if not state:
        return state, qr_str

    state, eth_view = process_hex_str(qr_str)
    if not state:
        return state, eth_view

    user_path = os.path.join(USER_DIR,'bossman.pickle')
    if not os.path.exists(user_path):
        # now this is brutal
        pass
    with open(user_path,'rb') as fd:
        udata = pickle.load(fd)

    udata['qr-str'] = qr_str
    udata['raw-eth-view'] = deepcopy(eth_view)

    with open(user_path,'wb') as fd:
        udata = pickle.dump(udata,fd)

    return True, eth_view


def main():
    s,d = housekeeping()
    if not s:
        sys.stderr.write(f'{d}\n')
        sys.exit(1)

    app_cfg, server_cfg = cp_setup()

    cherrypy.config.update(server_cfg)
    cherrypy.quickstart(Root(),'/txviewer',app_cfg)


if __name__=='__main__':
    # pid_path = pidder()
    main()
    # os.remove(pid_path)
