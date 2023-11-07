import "pe"
import "hash"

rule Demo_Rule_1_Fullword_PDB : APT {
   meta:
      description = "Rule that has a problematic fullword modifier"
      author = "Florian Roth"
      date = "2023-01-04"
      reference = "https://github.com/Neo23x0/yaraQA"
      score = 0
   strings:
      $s1 = "\\i386\\mimidrv.pdb" ascii wide fullword
   condition:
      all of them
}

rule Demo_Rule_2_Short_Atom : APT {
   meta:
      description = "Rule that has a short atom"
      author = "Florian Roth"
      date = "2023-01-04"
      reference = "https://github.com/Neo23x0/yaraQA"
      score = 0
   strings:
      $s1 = { 01 02 03 }
   condition:
      all of them
}

rule Demo_Rule_3_Fullword_FilePath_Section : APT {
   meta:
      description = "Rule that has a problematic fullword modifier"
      author = "Florian Roth"
      date = "2023-01-04"
      reference = "https://github.com/Neo23x0/yaraQA"
      score = 0
   strings:
      $s1 = "\\ZombieBoy\\" ascii fullword
   condition:
      all of them
}

rule Demo_Rule_4_Condition_Never_Matches : APT {
   meta:
      description = "Rule that looks for more strings than the rule actually has" 
      author = "Florian Roth"
      date = "2023-01-04"
      reference = "https://github.com/Neo23x0/yaraQA"
      score = 0
   strings:
      $s1 = "\\ZombieBoy\\" ascii
   condition:
      2 of them
}

rule Demo_Rule_5_Condition_Short_String_At_Pos : APT {
   meta:
      description = "Rule that looks for a short string at a particular position"
      author = "Florian Roth"
      date = "2023-01-04"
      reference = "https://github.com/Neo23x0/yaraQA"
      score = 0
   strings:
      $mz = "MZ" ascii
      $s1 = "dummy,dummy,dummy" xor(0x01-0xff)
   condition:
      $mz at 0 and 1 of them
}

rule Demo_Rule_6_Condition_Short_Byte_At_Pos : APT {
   meta:
      description = "Rule that looks for a short byte string at a particular position"
      author = "Florian Roth"
      date = "2023-01-04"
      reference = "https://github.com/Neo23x0/yaraQA"
      score = 0
   strings:
      $mz = { 4D 5A }
      $s1 = "dummy,dummy,dummy"
   condition:
      $mz at 0 and 1 of them
}

rule Demo_Rule_7_Path_Section_Fullword : APT {
   meta:
      description = "Rule that looks for a section of a path but uses fullword"
      author = "Florian Roth"
      date = "2023-01-06"
      reference = "https://github.com/Neo23x0/yaraQA"
      score = 0
   strings:
      $s1 = "\\Section\\in\\Path\\" ascii fullword
   condition:
      1 of them
}

rule Demo_Rule_8_Noob_Rule : APT {
   meta:
      description = "Rule that has strings with a bunch of modifiers which indicate that the author had no idea what he was doing and just decided to use them all."
      author = "Florian Roth"
      date = "2023-01-06"
      reference = "https://github.com/Neo23x0/yaraQA"
      score = 0
   strings:
      $s1 = "Usage: %s --killprocess" ascii wide nocase
   condition:
      1 of them
}

rule Demo_Rule_9_Uniform_String : APT {
   meta:
      description = "Rule that has strings which contents are very uniform / repetitive. This can cause problems with string matching resulting in 'too many string matches' errors."
      author = "Florian Roth"
      date = "2023-01-06"
      reference = "https://github.com/Neo23x0/yaraQA"
      score = 0
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
   condition:
      1 of them
}

rule Demo_Rule_10_Fullword_Path : APT {
   meta:
      description = "Rule that has strings that seem to be a path segment and use fullword."
      author = "Florian Roth"
      date = "2023-01-06"
      reference = "https://github.com/Neo23x0/yaraQA"
      score = 0
   strings:
      $s1 = "\\user.ini" fullword nocase
      $s2 = "\\\\SystemRoot\\test" fullword
   condition:
      uint16(0) == 0x5a4d and 1 of ($s*)
}

rule Demo_Rule_11_Fullword_Path_Duplicate : APT {
   meta:
      date = "2023-01-09"
      author = "Florian Roth (@cyb3rops)"
      score = 0
      description = "Rule that is logically equal to rule number 11 but has different meta data and string names"
      reference = "https://github.com/Neo23x0/yaraQA"
   strings:
      $s_dup1 = "\\USER.INI" fullword nocase
      $s_dup2 = "\\\\SystemRoot\\test" ascii fullword
   condition:
      1 of ($s_dup*) and uint16(0) == 0x5a4d
}

rule Demo_Rule_12_Only_PE : APT {
   meta:
      description = "Rule that is the only one in the set using the 'pe' module, which slows down the whole scan process"
      author = "Florian Roth (@cyb3rops)"
      date = "2023-01-09"
      reference = "https://github.com/Neo23x0/yaraQA"
      score = 0
   strings:
      $s1 = "\\USER.INI" fullword
   condition:
      pe.is_pe() and $s1
}

rule Demo_Rule_13_MZ_At_Pos : APT {
   meta:
      description = "Rule that looks for a short byte string at a particular position"
      author = "Florian Roth"
      date = "2023-01-04"
      reference = "https://github.com/Neo23x0/yaraQA"
      score = 0
   strings:
      $mz = "MZ"
   condition:
      $mz at 0
}

rule Demo_Rule_14_Hash_Calc_Fail : APT {
   meta:
      description = "Rule that calculates a hash over the whole file and compares it with a value (slows down the scan; YARA is not made for this)"
      author = "Florian Roth"
      date = "2023-01-10"
      reference = "https://github.com/Neo23x0/yaraQA"
      score = 0
   condition:
      hash.sha256(0, filesize) == "1a4a5123d7b2c534cb3e3168f7032cf9ebf38b9a2a97226d0fdb7933cf6030ff"
}

rule Demo_Rule_15_Entropy_Calc_Fail : APT {
   meta:
      description = "Rule that calculates the entropy over almost the whole file before the strings get checked (slows down the scan) - the order in the condition is important"
      author = "Florian Roth"
      date = "2023-01-10"
      reference = "https://github.com/Neo23x0/yaraQA"
      score = 0
   strings: 
      $ = "bypass"
   condition:
      math.entropy(500, filesize-500) >= 5.7 and all of them
}

rule Demo_Rule_16_Nocase_OnlyLetters : APT {
   meta:
      description = "Rule that uses nocase for a string that contains only letters"
      author = "Florian Roth"
      date = "2023-01-10"
      reference = "https://github.com/Neo23x0/YARA-Performance-Guidelines#string-advices"
      score = 0
   strings: 
      $ = "bypass" nocase
   condition:
      all of them
}

rule Duplicate_String_Rule {
    meta:
        author = "Matt Suiche (Magnet Forensics)"
        description = "Hunting Russian Intelligence Snake Malware"
        date = "2023-05-10"
        threat_name = "Windows.Malware.Snake"
        reference = "https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF"
        score = 75
        scan_context = "memory"
        license = "MIT"

    /* The original search only query those bytes in PAGE_EXECUTE_WRITECOPY VADs */
    strings:
        $a = { 25 73 23 31 }
        $b = { 25 73 23 32 }
        $c = { 25 73 23 33 }
        $d = { 25 73 23 34 }
        $e = { 2e 74 6d 70 }
        $f = { 2e 74 6d 70 }
        $g = { 2e 73 61 76 }
        $h = { 2e 75 70 64 }
    condition:
        all of them
}
