# flake8: noqa

import random
from math import gcd
import requests
import os
import binascii
import base64
import numpy as np
import time
import sys
import signal

image = """
                  Zyphen's Murder Room                                                                                
                                                                      
                            */*.                                                
                        #( (&&@@@@@@#.&*                                        
                  / %*#             (,& (,,&                                    
                 @@                   .. &@#                                    
                @.                         *& *#                                
              .@                         *   */@(.                              
           *%.@  .            ( # /&,&@%&  /@&%@ @(                             
           # @  %*   **  .*#*,*@@@@@&@@       @@@%@@#                           
           *@&&( . .(. % /@@,&@@@@@,&@         ((@@@&                           
            %&@ &, @.  , /@&@@@@@@.  &@%        .*@@@%                          
            @@(&@& (@ @ @,@@@@@@@*     &@        @@@@&                          
            @%@.@/ #&@@@(@@@@@&                  &@@.&                          
             @@@(@@.@@%//@@@@%&                  /@@@                           
              ./@(@&@@&@@@%@@(                   (@@                            
                @@(&&@@#@@@ &@*                  &@%                            
                 %@/(@@@@@@@  #                  @@/                            
                    &@,@@@@@@             ,*,   &%@&                            
                      &@@#&* @,                @#@ @%                           
                     & ,*@(@ %&@@#           &&@.     %                         
                      . /@@&@    @ @&#*,.  /. #                                 
                       .&/ / *              @%     #((*@ .*&@.                  
                       @  /@,                *  ,    ,                          
                      @&     / #@              %   */                           
                       *               /#%&&&%/ %   #@                          
                     *                              #.@                         
                     &%            .,                @/(                        
                     &(             .                .(                         
                     .&/             &               %@@&                       
                      *%             @                & (                       
"""
# Actually disgusting code but purposeful
# Dont think I am a bad coder

flag = open('/home/ctf/actualflag.txt','r').read()
masterkey = open('/home/ctf/master.txt','r').read()
flagr = open('/home/ctf/flag.txt','r').read()

MY_LUCKY_NUMBER = 736498

def multiplicative_inverse(a, m): 
    m0 = m 
    y = 0
    x = 1
  
    if (m == 1): 
        return 0
    while (a > 1): 
        q = a // m 
        t = m 
        m = a % m 
        a = t 
        t = y
        y = x - q * y 
        x = t 
    if (x < 0): 
        x = x + m0 
  
    return x 

def ripe_numbers(num):
    if num == 2:
        return True
    if num < 2 or num % 2 == 0:
        return False
    for n in range(3, int(num**0.5)+2, 2):
        if num % n == 0:
            return False
    return True

def wots_this(m, s):
    if not (ripe_numbers(m) and ripe_numbers(s)):
        raise ValueError('No')
    elif m == s:
        raise ValueError('Inequality is a must')
    p = m * s
    grek = (m-1) * (s-1)
    q = random.randrange(1, grek)
    g = gcd(q, grek)
    while g != 1:
        q = random.randrange(1, grek)
        g = gcd(q, grek)

    d = multiplicative_inverse(q, grek)
    lol = ((p, q), (d,p))
    return lol

def the_numbers(quack, wot):
    blood, p = quack
    ceaser = [((ord(char) ** blood)) % p for char in wot]
    return ceaser

def hide_evidence():
  s = 0
  m = 20000
  for i in range(random.randint(498,736)):
    m += random.randint((MY_LUCKY_NUMBER - 736400), 73649)
    s = random.randint((MY_LUCKY_NUMBER - 736400), 73649)
  d = m * s
  s -= random.randint(1, 2)
  return random.randint(s,d)

def splatter(meat,blood):
  mess = []
  mess.append(blood)
  a = blood
  b = hide_evidence()
  c = hide_evidence()
  d = hide_evidence()
  for i in range(len(meat)-1):
    a = (a*b+c)%d
    mess.append(a)
  return mess

def prepare(meat):
  fresh = []
  for i in range(len(meat)):
    fresh.append(meat[i]^MY_LUCKY_NUMBER)
  for k in range(len(fresh)):
    fresh[i] += MY_LUCKY_NUMBER
  return fresh

def torture(meat,blood):
  baked = splatter(meat,blood)
  treasure = []
  for i in range(len(baked)):
    treasure.append(ord(meat[i])*baked[i])
  treasure = prepare(treasure)
  return treasure

print(image)
blood = hide_evidence()
saliva = hide_evidence()
bcleaner = blood * (MY_LUCKY_NUMBER - 736000) - 1
scleaner = saliva * (MY_LUCKY_NUMBER - 736000) - 1

while not (ripe_numbers(bcleaner)):
  blood = hide_evidence()
  bcleaner = blood * (MY_LUCKY_NUMBER - 736000) - 1

while not (ripe_numbers(scleaner)):
  saliva = hide_evidence()
  scleaner = saliva * (MY_LUCKY_NUMBER - 736000) - 1

u, v = wots_this(bcleaner, scleaner)

def convert_to_ascii(text):
    return "".join(str(ord(char)) for char in text)

def geom(a,k,n):
    if k <= 2:
        return sum(a**i for i in range(k)) % n
    else:
        m = k//2
        b = pow(a,2,n)
        g = ((1+a)*geom(b,m,n))%n
        return g if k%2 == 0 else (g + pow(a,k-1,n))%n

def f(a,m,n):
    k = len(str(a))
    r = pow(10,k,n)
    return (a*geom(r,m,n))%n

rf = int(convert_to_ascii("PLEASEHELPMEINEEDTOGETOUT"))

def reverse(str):
    s = ""
    for ch in str:
        s = ch + s
    return s

funroom = open('/home/ctf/funroom.txt','r').read()

modman = f(rf, u[1], u[0])

caesar = str(torture("*DONT TRUST THE E*... shut up " + reverse(funroom),modman))

print("Ciphertext: " + caesar)
print("N: " + str(u[0]))
print("E: " + str(u[1]))

inputkey = input("What is the key? ")

xecrets = ["[REDACTED]", "[REDACTED]", "[REDACTED]"]
answerscheck = ["[REDACTED]", "[REDACTED]", "[REDACTED]"]
x = np.random.choice([0,1,2])
acx = np.random.choice([0,1,2])

xchoice = xecrets[x]

achoice = answerscheck[acx]

def hexify(str):
    return int(str,base=16)

def two_str(str1,str2):
    a = hexify(str1)
    b = hexify(str2)
    return hex(a ^ b)

z = two_str(achoice, f"{xchoice}")

asciistr = bytes.fromhex(achoice.lstrip('0x')).decode("ASCII")

class TimeoutException(Exception):
    pass

def sigalrm_handler(signum, frame):
    raise TimeoutException()

if inputkey == masterkey:
  print("You got out of your room?! Impossible! I guess use your compensation... Maybe I will be back, but you aren't done yet... QUICK WHAT IS THE FLAG")
  print(f"x = {xchoice[2:]} \n z = {str(z)[2:]}")
  old_handler = signal.signal(signal.SIGALRM, sigalrm_handler)
  signal.alarm(3)
  try:
    inputflag = input("What is the key?!?!?!?!?!??! ")
    if inputflag == asciistr:
        print("\n")
        print("\n")
        print(flag)
    else:
        print("\nWrongggg and toooooo slow!!! Did you really think you were any good at crypto? >:) >:) Time for your pain and suffering!!")   
  except TimeoutException:
    print("\nWrongggg and toooooo slow!!! Did you really think you were any good at crypto? >:) >:) Time for your pain and suffering!!")   
else:
    print("\nTime for your pain and suffering!!")