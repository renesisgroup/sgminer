#!/bin/bash

export GPU_USE_SYNC_OBJECTS=1 
export GPU_MAX_ALLOC_PERCENT=100 

./sgminer -c sgminer.conf
