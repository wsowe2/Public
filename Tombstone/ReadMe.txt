Settings explanation:

EmailRecipients: users, DLs, etc that will receive the daily emails about what was done. we send these to our service desk and level 2 teams
ReallyDisable: boolean toggle to actually disable machines moved into your tombstone OU
MaxComps: the maximum number of machines affected on any given run. in case something is wrong, you don't blow up your whole environment on the first day
ReallyDelete: same as disable, boolean to delete or not
TombstoneAge: days a machine has been offline before moving it to the tombstone OU
Cleanup: whether to move newly re-enabled machines from the tombstone OU to their originating OU (if logged) or the default OU
DeleteAge: number of days before deleting/backing-up machines in the tombstone OU

The "Really" settings are what i decided to setup so that we could run the script for a few weeks to see what the results were gonna look like before implementing it in production. MaxComps is just something I did because we had a couple thousand machines that were backed up in our tombstone OU because our previous process failed after some security changes. I had set it so that we would only adjudicate 100 machines at most on any given run. it took the better part of a month to clean up all of them but it calmed down after that. the Ages should be self-explanatory. Cleanup is just to toggle taking machines that were re-enabled after being tombstones but before being deleted and it uses the CSV to remit the machine back to it's starting OU if it was logged and our default SCCM OU if not.

I would highly recommend running it in the logging mode for a few weeks just to see if everything is gonna blow up. once you decide to put it into production, I would clear all of the entries in the CSV for the BL keys and the OU logging CSV. I also setup security on the "Secure" folder so that only my team and our InfoSec team could access it and placed the ps1 itself in that secure folder so no one gets in it and messes anything up. I also setup a 24 hour delay on moving devices into tombstone and setting them as disabled. the reason being, we give our SCCM environment a chance to see that those machines are moved into the tombstone folder and we stop running any inventories on them when they become tombstoned. the script uses the "disabled" CSV from the previous day to get the list of the machines to disable on the current run. this may cause some confusion or issues if you're not aware of it.

The script itself has a few variables you will need to setup for your environment. if you do a search for % it will take you to the variables as well as what the expected info would be.

we keep all of our endpoints in an OU called "Workstations" and we put our Tombstone OU in there as well. we have an OU called SCCM which is our "default" OU for machines that get imaged from SCCM and that is also inside the workstations OU.

Lastly there's an EXCLUDE OUs text file that you can put the DN of an OU on each individual line. the script will pass over that OU and anything below it and won't look for machines to be disabled/deleted. We have a few OUs that needed to be excluded from the process and we have used it a few times to temporarily take a location out of the process because the facilities were damaged.