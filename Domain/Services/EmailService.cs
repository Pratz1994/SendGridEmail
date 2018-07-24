using System;
using System.Linq;
using System.Threading.Tasks;
using SendGrid;
using System.Net;
using System.Diagnostics;
using System.Net.Mail;
using Mars.Services.Identity.Domain.Contracts;
using static Microsoft.AspNetCore.Hosting.Internal.HostingApplication;
using Microsoft.IdentityModel.Protocols;

namespace Mars.Services.Identity.Domain.Services
{
    public class EmailService : IIdentityMessageService
    {
        public async Task SendAsync(IdentityMessage message)
        {
            await configSendGridasync(message);
        }


        private async Task configSendGridasync(IdentityMessage message)
        {
            var myMessage = new SendGridMessage();
            //myMessage.AddTo(message.Destination);
            myMessage.From = new MailAddress("Royce@contoso.com", "Royce Sellars (Contoso Admin)");
            myMessage.Subject = message.Subject;
            myMessage.Text = message.Body;
            myMessage.Html = message.Body;

            var credentials = new NetworkCredential(
                       ConfigurationManager.AppSettings["emailServiceUserName"],
                       ConfigurationManager.AppSettings["emailServicePassword"]
                       );

            // Create a Web transport for sending email.
            var transportWeb = new Web(credentials);

            // Send the email.
            if (transportWeb != null)
            {
                await transportWeb.DeliverAsync(myMessage);
            }
            else
            {
                Trace.TraceError("Failed to create Web transport.");
                await Task.FromResult(0);
            }
        }

  
    }
}
