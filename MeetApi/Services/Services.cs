using MeetApi.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Net;
using System.Net.Mail;

namespace MeetApi.Services
{
    public class PasswordRecovery
    {
        public void PasswordRecoveryMail(ApplicationUser user, string Password)
        {
            String FROM = "info@teamigroup.com";
            String FROMNAME = "Crew Meet";
            String TO = user.Email;
            String SMTP_USERNAME = "info@teamigroup.com";
            String SMTP_PASSWORD = "ti10203040$";
            String CONFIGSET = "ConfigSet";
            String HOST = "mail.teamigroup.com";
            int PORT = 587;
            String BODY = "Your new password is " + Password + " you can use it to login and change your password";
            MailMessage message = new MailMessage();
            message.IsBodyHtml = true;
            message.From = new MailAddress(FROM, FROMNAME);
            message.To.Add(new MailAddress(TO));
            message.Subject = "Account Recovery";
            message.Body = BODY;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            var client = new SmtpClient(HOST, PORT);
            client.Credentials = new NetworkCredential(SMTP_USERNAME, SMTP_PASSWORD);
            client.EnableSsl = true;
            client.Send(message);
        }
        public string GeneratePassword(int Length)
        {
            Random random = new Random();
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            return new string(Enumerable.Repeat(chars, Length)
              .Select(s => s[random.Next(s.Length)]).ToArray());
        }
    }
}
