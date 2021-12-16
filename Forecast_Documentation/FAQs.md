# Frequently Asked Questions and Common Issues

### *I am encountering errors when pip installing cle / angr / simprocedures. What should I do?*
Some users have had issues installing cle / angr / simprocedures, but have had those issues resolved after installing `.[dev]`. If you are encountering these issues, please install `.[dev]` and try again.

### *Can Forecast be installed on Windows?*
Forecast cannot currently be installed on Windows. It can, however, be installed on a Debian / Ubuntu virtual machine or Docker image.

### *When I try to run Forecast on my memory dump, I receive an error that says: “Unable to find a loader backend for sample_dump.dmp” why am I getting this error?*
If you are getting this error, your memory dump likely is not compatible with Forecast. For instance, memory dumps from WinDbg are currently incompatible with Forecast. For tested methods of generating memory dumps, please refer to the “Collecting a memory image” section of the [step-by-step guide](https://github.com/dizmascyberlabs/ForecastDocumentation/blob/main/Step_by_Step.md).

### *I know my sample malware was performing malicious activities, although Forecast is not detecting them. Why?*
There are numerous reasons why Forecast may not detect malicious activity. First, the results of Forecast depend on the state of the memory when the dump was taken. It is possible the malicious activity was not in memory when the dump was collected.

It is also possible that Forecast does not detect the particular functions that the malware sample is using. Forecast does detect many common functions used by malware to conduct malicious activity, although it cannot account for every function that a malware may use. If this is the case, it is possible to extend Forecast to detect more functions.

It is also possible that Forecast did not find the correct path to explore the malware. While Forecast’s symbolic analysis is robust, it is not always perfect. If this is the case, the user can troubleshoot Forecast by adding debug prints in the Forecast python code. This way, the user can monitor how Forecast is exploring the memory dump and find where it is getting sidetracked.

### *Forecast has detected c&c activity in my memory dump, although it does not appear to be the correct domain. Why is it giving me this value instead?*
Depending of the state of the memory, the domain may have not been initialized yet. If this is the case, the domain reported by Forecast may not be accurate.

### *How do I extend existing plugins?*
You can extend existing plugins by modifying its particular plugin file in the `plugins` directory, as well as adding the necessary information into the correct `simprocedure` file.
For instance, to add HttpSendRequest to the c&c detection plugin, find the file `foresee/plugins/cc_domain_detection.py` add HttpSendRequest to the list called `functions_monitored` as well as adding a case `if proc_name == "HttpSendRequest"`, in the format of the other cases. From there, you should add a class in the `simprocedures/simprocedures/win32/wininet.py` file, in the same format as the other classes.
After extending Forecast, you may have to pip install simprocedures again in order for the changes to be implemented.
