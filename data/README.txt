The "data" directory is intended to hold data files that will be used by this module and will
not end up in the .jar file, but will be present in the zip or tar file.  Typically, data
files are placed here rather than in the resources directory if the user may need to edit them.

An optional data/languages directory can exist for the purpose of containing various Sleigh language
specification files and importer opinion files.  

The data/buildLanguage.xml is used for building the contents of the data/languages directory.

The skel language definition has been commented-out within the skel.ldefs file so that the 
skeleton language does not show-up within Ghidra.

See the Sleigh language documentation (docs/languages/index.html) for details Sleigh language 
specification syntax.
 
 ####### OP Preludes

extRegVal: wReg5_3 is (opData5_3=0 | opData5_3=1 | opData5_3=2 | opData5_3=3) & wReg5_3 { tmp:3 = (DP << 16) + wReg5_3; export tmp; }
extRegVal: wReg5_3 is (opData5_3=4 | opData5_3=5) & wReg5_3 { tmp:3 = (EP << 16) + wReg5_3; export tmp; }
extRegVal: wReg5_3 is (opData5_3=6 | opData5_3=7) & wReg5_3 { tmp:3 = (UTP << 16) + wReg5_3; export tmp; }

bFpOffset: @(simm4_4,FP) is op0_4=0x2 & simm4_4 & FP { ptr:3 = segment(UTP,FP); ptr = ptr + sext(simm4_4:1); export *:1 ptr; }
wFpOffset: @(simm4_4,FP) is op0_4=0x3 & simm4_4 & FP { ptr:3 = segment(UTP,FP); ptr = ptr + sext(simm4_4:1); export *:2 ptr; }

bImmAddr11: val is op0_4=0x8 & opHalf4_1=0x0 & opData5_3; imm8 [ val = (opData5_3 << 8) + imm8; ] { tmp:3 = zext(val:2); export *:1 tmp; }
wImmAddr11: val is op0_4=0x8 & opHalf4_1=0x1 & opData5_3; imm8 [ val = (opData5_3 << 8) + imm8; ] { tmp:3 = zext(val:2); export *:2 tmp; }

bRW2Offset: @(simm16,extRegVal) is op0_4=0x9 & opHalf4_1=0x0 & extRegVal; simm16 { ptr:3 = extRegVal + sext(simm16:2); export *:1 ptr; }
wRW2Offset: @(simm16,extRegVal) is op0_4=0x9 & opHalf4_1=0x1 & extRegVal; simm16 { ptr:3 = extRegVal + sext(simm16:2); export *:2 ptr; }

bRWOffset: @(simm8,extRegVal) is op0_4=0xA & opHalf4_1=0x0 & extRegVal; simm8 { ptr:3 = extRegVal + sext(simm8:1); export *:1 ptr; }
wRWOffset: @(simm8,extRegVal) is op0_4=0xA & opHalf4_1=0x1 & extRegVal; simm8 { ptr:3 = extRegVal + sext(simm8:1); export *:2 ptr; }

bRWAddr: @(extRegVal) is op0_4=0xB & opHalf4_1=0x0 & extRegVal { export *:1 extRegVal; }
wRWAddr: @(extRegVal) is op0_4=0xB & opHalf4_1=0x1 & extRegVal { export *:2 extRegVal; }

rbDir: bReg5_3 is op0_4=0x1 & opHalf4_1=0x0 & bReg5_3 { export bReg5_3; }
rbDirAlt: bReg5_3 is op0_4=0xC & opHalf4_1=0x0 & bReg5_3 { export bReg5_3; }
rwDir: wReg5_3 is op0_4=0xC & opHalf4_1=0x1 & wReg5_3 { export wReg5_3; }

bOpImm3: opData5_3 is op0_4=0xD & opHalf4_1=0x0 & opData5_3 { tmp:1 = zext(opData5_3:1); export tmp; }
wOpImm3: opData5_3 is op0_4=0xD & opHalf4_1=0x1 & opData5_3 { tmp:2 = zext(opData5_3:1); export tmp; }

bAddrAbs16: val is op0_8=0xE0; imm16 [ val = (DP << 16) + imm16; ] { export *:1 val; }
bAddrAbs24: immAddr24 is op0_8=0xE1; immAddr24 { export immAddr24; }
bOpImm8: immVal8 is op0_8=0xE2; immVal8 { export immVal8; }

# :POP.B ? is op0_8=0xE7

wAddrAbs16: val is op0_8=0xE8; imm16 [ val = (DP << 16) + imm16; ] { export *:2 val; }
wAddrAbs24: wImmAddr24 is op0_8=0xE9; wImmAddr24 { export wImmAddr24; }
wOpImm16: immVal16 is op0_8=0xEA; immVal16 { export immVal16; }
wOpImm8: immVal8 is op0_8=0xFE; immVal8 { tmp:2 = zext(immVal8); export tmp; }

# :POP.W ? is op0_8=0xEF
# :TBL5 ? is op0_8=0xF3