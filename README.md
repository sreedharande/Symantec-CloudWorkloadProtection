# Symantec Cloud Workload Protection
Microsoft Sentinel Data connector to ingest Symantec Cloud Workload Protection (CWP) events using CWP REST API at: https://apidocs.symantec.com/home/scwp#_symantec_cloud_workload_protection

## Installation / Setup Guide

1. Click  Deploy To Azure/Deploy to Azure Gov  
[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/)



2. Select the preferred **Subscription**, **Resource Group** and **Location**  
   **Note**  
   Best practice : Create new Resource Group while deploying - all the resources of your custom Data connector will reside in the newly created Resource 
   Group
3. Enter the parameter values in the ARM template deployment
	

## Post Deployment Steps

1. The `TimerTrigger` makes it incredibly easy to have your functions executed on a schedule. This sample demonstrates a simple use case of calling your function based on your schedule provided while deploying. If the time interval needs to be modified, it is recommended to change the Function App Timer Trigger accordingly update environment variable **"Schedule**" (post deployment) to prevent overlapping data ingestion.
   ```
   a.	Go to your Resource Group --> Click on Function App `<<functionappname>><<uniqueid>>`
   b.	Click on Function App "Configuration" under Settings 
   c.	Click on "Schedule" under "Application Settings"
   d.	Update your own schedule using cron expression.
   ```
   **Note: For a `TimerTrigger` to work, you provide a schedule in the form of a [cron expression](https://en.wikipedia.org/wiki/Cron#CRON_expression)(See the link for full details). A cron expression is a string with 6 separate expressions which represent a given schedule via patterns. The pattern we use to represent every 10 minutes is `0 */10 * * * *`. This, in plain text, means: "When seconds is equal to 0, minutes is divisible by 10, for any hour, day of the month, month, day of the week, or year".**
   
 
2. Parameterized Symantec Cloud Workload Protection event duration using environment variable "FreshEventTimeStamp". Value must be in minutes.  
   **Note**  
   Azure Function trigger schedule and FreshEventTimeStamp
   Ex: If you want to trigger function every 30 min then values must be
   FreshEventTimeStamp=30
   Schedule=0 */30 * * * *
      
4. ClientID, ClientSecret and Workspace Key will be placed as "Secrets" in the Azure KeyVault `<<functionappname>><<uniqueid>>` with only Azure Function access policy. If you want to see/update these secrets,

	```
		a. Go to Azure KeyVault "<<functionappname>><<uniqueid>>"
		b. Click on "Access Policies" under Settings
		c. Click on "Add Access Policy"
			i. Configure from template : Secret Management
			ii. Key Permissions : GET, LIST, SET
			iii. Select Prinicpal : <<Your Account>>
			iv. Add
		d. Click "Save"

	```