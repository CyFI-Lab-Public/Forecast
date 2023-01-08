# Forecast
Forecasting Malware Capabilities From Cyber Attack Memory Images

## Foreword
Before working with Forcast please make sure to read the 
[Forcast paper](https://cyfi.ece.gatech.edu/publications/SEC_21.pdf) 
as it will help with understanding and extending the tool if necessary!
Keep in mind that this tool is still not perfect, errors are not uncommon and knowing how to work with angr is essential.

With that being said Forecast is an incredible tool to speeds up analysis and can get you some insight into what a sample does without manually reversing it. Included are some sample memory images in (../Forcast/sample_dumps/windows_dynamic_loading/Dump) to illustrate in simple cases what Forsee is capable of.

This code is provided as is. If you extend it in any way/fix any bugs, then please reach out. We will be glad to incorporate any upgrades and give you due credit! :)

## Requirements
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

Ubuntu 20.04 and above
    Set-up of Virtual Environment
    1. sudo apt-get install -y python3-pip
    2. sudo apt-get install build-essential libssl-dev libffi-dev python-dev
    3. sudo apt-get install -y python3-venv
    4. python3 -m venv name_of_virtual_environment
    5. source activate  path/to/bin/in/virtual/environment
    
    Within virtual environment
    1)Install python module 'six': pip install six
    2)Set protbuf to 3.20:  pip install protobuf==3.20.*
    
    Install angr, cle and dependencies follow the method above
 

## Using Forcast
1) Get a memory image of a sample using the numerous methods there are.
2) Navigate in the terminal to your forsee-arm directory, if the virtual environment is not activated proceed to activate it with 
`. ./venv/bin/activate`
3) Navigate in a terminal to `/Forcast/scripts` to use the script `run_minidump.py` .
4) General usage of run_minidump.py is `python run_minidump.py ../path/to/saved/minidump arg1 val1 arg2 val2 ....` Where arg1 val1, arg2 val2, etc are optional arguments that get added to an angr project. For example, if I wanted to specify that my minidump has 64 bit architecture and I wanted to use a blob backend I would write: `python run_minidump.py ../path/to/saved/minidump backend blob arch amd64`
5) You can see shortly if anything was detected within your minidump from the plugin system!

Using Main.dmp located in ../Forcast/sample_dumps/windows_dynamic_loading/Dump we run Forcast on that memory image with: 
`python run_minidump.py '/home/ubuntu/Desktop/Forcast/sample_dumps/windows_dynamic_loading/Dump'`

You can also use on /Forcast the script `run_forsee.py` which takes no arguments but the script needs to be modified with a different path to a memory image every time it is to be used.

Included in `/Forcast/sample_dumps/windows_dynamic_loading` is also a memory image of the sample greencat, where you can test some simple usage of Forcast.

Please make sure to only use 32 bit memory images!

Have issues using Forecast? Check out [the FAQs page](Forecast_Documentation/FAQs.md). If you have something to add, please submit a pull request.

## Plugin System
A plugin system is implemented to allow plugins to receive callbacks from triggered breakpoints and access the 
`SimManager` after each step.

To create a new plugin, make a new file in the `plugins` folder containing your plugin as a subclass of `PluginBase`. 
Next, add the new plugin class to `plugin_list` in `PluginManager`.

