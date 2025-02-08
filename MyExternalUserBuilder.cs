using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Sitecore.Owin.Authentication.Services;
using System.Security.Claims;
using System.Net;
using Sitecore.Security.Domains;
using Sitecore.SecurityModel.Cryptography;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Identity;
using System;
using System.Linq;

using Sitecore.Diagnostics;



namespace AzureAdProvider
{
    public class MyExternalUserBuilder : DefaultExternalUserBuilder
    {

        private string srcDomainName = "sitecore";
        private string destDomainName = "ADdomain";


        public MyExternalUserBuilder(ApplicationUserFactory applicationUserFactory, IHashEncryption hashEncryption) : base(applicationUserFactory, hashEncryption) { }


        public override ApplicationUser BuildUser(UserManager<ApplicationUser> userManager, ExternalLoginInfo externalLoginInfo)
        {
            Sitecore.Diagnostics.Log.Info($"Inside BuildUser ", this);
            ApplicationUser user = this.ApplicationUserFactory.CreateUser(this.CreateUniqueUserName(userManager, externalLoginInfo));
            user.IsVirtual = !this.IsPersistentUser;

            MapADuserToScUser(externalLoginInfo, user);


            return user;
        }

        protected override string CreateUniqueUserName(Microsoft.AspNet.Identity.UserManager<ApplicationUser> userManager, ExternalLoginInfo externalLoginInfo)
        {


            Assert.ArgumentNotNull((object)userManager, nameof(userManager));
            Assert.ArgumentNotNull((object)externalLoginInfo, nameof(externalLoginInfo));
            IdentityProvider identityProvider = this.FederatedAuthenticationConfiguration.GetIdentityProvider(externalLoginInfo.ExternalIdentity);
            if (identityProvider == null)
                throw new InvalidOperationException("Unable to retrieve identity provider for given identity");


            string externalEmail = getEmailClaim(externalLoginInfo).Value.ToLower();
            Func<string, string> getLocalPart = email => string.IsNullOrEmpty(email) ? "" : email.Split('@')[0];
            string validUserName = getLocalPart(externalEmail);
            //       Sitecore.Diagnostics.Log.Info($"In CreateUniqueUserName: domain is {destDomainName} and username is {validUserName}", this);

            return $"{destDomainName}\\{validUserName}";
        }

        private void MapADuserToScUser(ExternalLoginInfo externalLoginInfo, ApplicationUser newScUser)
        {

            string externalEmail = getEmailClaim(externalLoginInfo).Value;
            Sitecore.Diagnostics.Log.Warn($"AzureAdProvider: Retrieved External Email: {externalEmail}.", this);


            newScUser.Email = externalEmail.ToLower();

                        newScUser.InnerUser.Profile.Save();
            Sitecore.Diagnostics.Log.Info("User " + newScUser.UserName + " was successfully created", this);

        }

        public Sitecore.Security.Accounts.User FindUserByEmail(string domainName, string email)
        {
            // Get the list of all users in the Sitecore domain
            var domain = Domain.GetDomain(domainName);
            if (domain == null)
            {
                Sitecore.Diagnostics.Log.Warn("Sitecore domain not found.", this);
                return null;
            }

            // Iterate through users in the domain
            foreach (var user in domain.GetUsers())
            {
                // Load the user profile
                var userProfile = user.Profile;
                if (userProfile != null && userProfile.Email.Equals(email, StringComparison.OrdinalIgnoreCase))
                {
                    Sitecore.Diagnostics.Log.Info($"User found in Sitecore database with email {email}.", this);
                    return user; // Return the matching user
                }
            }

            // Return null if no match is found
            Sitecore.Diagnostics.Log.Warn($"No user found with email {email}.", this);
            return null;
        }

        private Claim getEmailClaim(ExternalLoginInfo externalLoginInfo)
        {
            if (externalLoginInfo?.ExternalIdentity == null)
            {
                Sitecore.Diagnostics.Log.Warn("ExternalLoginInfo or ExternalIdentity is null.", this);
                return null;
            }
            var emailClaim = externalLoginInfo.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email || c.Type == "email");
            if (emailClaim == null || string.IsNullOrEmpty(emailClaim.Value))
            {
                Sitecore.Diagnostics.Log.Warn("No email claim found in external login info.", this);
                return null;
            }

            return emailClaim;
        }




    }
}
