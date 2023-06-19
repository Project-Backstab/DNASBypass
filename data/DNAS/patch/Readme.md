# PCSX 2 Patch

When you want to extract the information automaticly you can use this patch in the PCSX2 emulator.

## How to apply?

First you need to get the pcsx2 project and compile. I dont give any instructions how to do this. USe your google skills ;)

Second you to find the following file in the pcsx2 project "IR5900-32.cpp".
Find the "recompileNextInstruction" and replace it with my code that it will execute our two new scan functions.