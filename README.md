# Forecast
Forecasting Malware Capabilities From Cyber Attack Memory Images

# Foreword
Before working with Forcast please make sure to read the 
[Forcast paper]() 
as it will help with understanding and extending the tool it if necessary!
Keep in mind that this tool is still not perfect, errors are not uncommon and knowing how to work with angr is essential.

With that being said Forecast is an incredible tool to speeds up analysis and can get you some insight into what a sample does without manually reversing it. Included are some sample memory images in (../Forcast/sample_dumps/windows_dynamic_loading/Dump) to illustrate in simple cases what Forsee is capable of.

# Requirements
Forcast has been primarily used on Ubuntu 14.xx and 18.xx machines and has been tested to work on those OS, but results may vary if using something else. Make sure to have all packages up to date and install prerequisites, as well as git. Make sure Pip is also installed and upgraded: python3 -m pip install --upgrade pip

Python3.7-dev - Will not work without dev. Use: sudo apt install python3.7-dev

Python3.7-venv Also needed to create virtual environment, use: sudo apt install python3.7-venv

Once this repository is cloned: `git clone https://github.com/CyFI-Lab-Public/Forecast.git`

Navigate to /Forecast and create/activate the virtual environment then install angr, cle, simprocedures, and dependencies.
1) Setup the virtual environment `python3.7 -m venv venv`
2) Activate the virtual environment `. ./venv/bin/activate`
3) Install custom cle `pip install -e ../path/to/Forcast/cle`
4) Install custom angr `pip install -e ../path/to/Forcast/angr`
5) Install simprocedures `pip install -e ../path/to/Forcast/simprocedures`
6) Install forsee and dependencies `pip install -e .[dev]`

## Using Forcast
1) Get a memory image of a sample using the numerous methods there are.
2) Navigate in the terminal to your forsee-arm directory, if the virtual environment is not activated proceed to activate it with 
`. ./venv/bin/activate`
3) Navigate in a terminal to `/Forcast/scripts` to use the script `run_minidump.py` .
4) General usage of run_minidump.py is `python run_minidump.py ../path/to/saved/minidump arg1 val1 arg2 val2 ....` Where arg1 val1, arg2 val2, etc are optional arguments that get added to an angr project. For example, if I wanted to specify that my minidump has 64 bit architecture and I wanted to use a blob backend I would write: `python run_minidump.py ../path/to/saved/minidump backend blob arch amd64`
5) You can see shortly if anything was detected within your minidump from the plugin system!

Using Main.dmp located in ../Forcast/sample_dumps/windows_dynamic_loading/Dump we run Forcast on that memory image with: 
`python run_minidump.py '/home/ubuntu/Desktop/Forcast/sample_dumps/windows_dynamic_loading/Dump`

You can also use on /Forcast the script `run_forsee.py` which takes no arguments but the script needs to be modified with a different path to a memory image every time it is to be used.

## Plugin System
A plugin system is implemented to allow plugins to receive callbacks from triggered breakpoints and access the 
`SimManager` after each step.

To create a new plugin, make a new file in the `plugins` folder containing your plugin as a subclass of `PluginBase`. 
Next, add the new plugin class to `plugin_list` in `PluginManager`.

## Questions
Please feel free to email us if you have any questions, improvements to Forcast, etc! :)

