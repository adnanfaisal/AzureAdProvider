# AzureAdProvider
Custom code for Sitecore's ExternalUserBuilder. It shows
1) How to give meaningful names to the users (instead of the default random string)
2) How to make email transformation via code
3) Creating Entra ID users in a separate domain (e.g., ADdomain) than the default "sitecore" domain. Note that, in such case for claim transormations to work properly, all the roles to be used for transformation should also belong to the same domain (e.g., ADdomain). 
