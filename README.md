# Aletheia-Analyzer

## Introduction
Aletheia is a tool built for distributed low-end robust wireless R&D platforms (e.g., raspberry pis, jetson, etc.). Aletheia analyzer enables its users to select subset of logged medium data, tag and view frames based on custom general attributes defined by user or conditional.

## Getting Started 
To run code with sample described view (stored in config.txt) processed on sample logged data binary file (output.bin) that had selective filtering described in ADF file (ADF.txt), please run the following command:
```
python Analyzer.py
```

A graph should show up displaying final output of multiple mac addresses all tagged.


### config.txt

The following describes structure of config.txt and how it works:
.tag  beginning of 'tag' section
attribute-target-key = describes key of the attributes user is interested in tagging
tag-label = text describing what the attribute is for the user (for custom viewing and external view)
val= can be either 'all' or specific values user is interested in tagging.
.view beginning of 'view' section (describe parameters for viewing e.g., start/end, tick size, etc.)
granularity = x tick granularity in microseconds
start = start time of graph from beginning of log in microseconds
duration = duration of which graph is visualized, in microseconds
end= end of section.


## TO DO:
1. allow custom tagging instead of just all
2. enable conditional attribute tagging
3. add parameters and ops with flexible configurations
4. allow labelling of visualizer information


