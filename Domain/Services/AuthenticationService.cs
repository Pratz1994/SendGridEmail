using Mars.Common.Auth;
using Mars.Common.Contracts;
using Mars.Common.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using MongoDB.Bson;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Threading.Tasks;
using static Microsoft.AspNetCore.Hosting.Internal.HostingApplication;


namespace Mars.Services.Identity.Domain.Services
{
    public class AuthenticationService: IAuthenticationService
    {
        // These constants may be changed without breaking existing hashes.
        public const int SALT_BYTES = 24;
        public const int HASH_BYTES = 18;
        public const int PBKDF2_ITERATIONS = 64000;

        private IRepository<User> _userRepository;
        private IRepository<Login> _loginRepository;
        private IPasswordStorage _encryptPassword;
        private UserManager _userManager;
        private IJwtHandler _jwtHandler;
        private EmailService _emailService;

        public AuthenticationService(IRepository<User> userRepository,
                                IRepository<Login> loginRepository,
                                IPasswordStorage encryptPassword,
                                IJwtHandler jwtHandler,
                                 UserManager userManager,
                                 EmailService emailService)
        {
            _emailService = emailService;
            _userManager = userManager;
            _userRepository = userRepository;
            _loginRepository = loginRepository;
            _encryptPassword = encryptPassword;
            _jwtHandler = jwtHandler;
        }
        /// <summary>
        /// Register new customer
        /// </summary>
        /// <param name="user"></param>
        public async Task Register(SignUpPersonal user)
        {
            try
            {
                if (user == null) throw new ApplicationException("Incomplete register request - user is null");
                if (user.EmailAddress == null) throw new ApplicationException("Incomplete register request - user's email is null");
                if (user.Password == null || user.Password.Length == 0) throw new ApplicationException("Incomplete register request - Password is null");
                var existingUser = _userRepository.Get(x => x.Login.Username == user.EmailAddress).FirstOrDefault();
                if (existingUser != null)
                {
                    throw new ApplicationException("Email address has been used in registration.");
                }

                // hash password
                var passHash = _encryptPassword.CreateHash(user.Password);

                //var passHash = new PBKDF2(user.Password,SALT_BYTES,PBKDF2_ITERATIONS,"HMACSHA512");
                var UId = Guid.NewGuid();
                var objectId = ObjectId.GenerateNewId().ToString();
                var login = new Login()
                {
                    Id = objectId,
                    UId = UId,
                    Username = user.EmailAddress,
                    PasswordHash = passHash,
                    IsDisabled = true,
                    EmailAddressAuthorized = false,
                    EmailCode = user.EmailCode,
                    ExpiredOn = DateTime.UtcNow.AddHours(24),
                    PasswordFormat = PBKDF2_ITERATIONS,
                    TermsAccepted = user.TermsConditionsAccepted
                };

                var person = new User()
                {
                    Id = objectId,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    MobilePhone = user.MobileNumber,
                    CreatedOn = DateTime.UtcNow,
                    IsDeleted = false,
                    UId = UId,
                    Login = login,
                };

                await _userRepository.Add(person);

            }
            catch (Exception ex)
            {
                throw new ApplicationException("Register error - " + ex.Message);
            }
        }

        /// <summary>
        /// Verify password
        /// </summary>
        /// <param name="email"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public async Task<bool> VerifyPassword(string email, string password)
        {
            //TODO for testing purpose
            if (string.IsNullOrEmpty(password)) throw new ApplicationException("Login fail - Password is null");

            var user = _userRepository.GetQueryable().Where(x => x.Login.Username.Equals(email)).FirstOrDefault();
            if (user == null) throw new ApplicationException("Login fail - user is null");

            return _encryptPassword.VerifyPassword(password, user.Login.PasswordHash);
        }

        public async Task ResetPassword(Login user, string newPassword)
        {
            if (user == null) throw new ApplicationException("Incomplete reset password - user is null");
            // hash password
            var passHash = _encryptPassword.CreateHash(newPassword);
            user.PasswordHash = passHash;

            await _loginRepository.Update(user);

        }

        public async Task<JsonWebToken> LoginAsync(string email, string password)
        {
            var user = _userRepository.Get(x=> x.Login.Username == email).FirstOrDefault();
            if(user == null)
            {
                throw new ApplicationException("Invalid credentials");
            }
            var passwordCorrect = await VerifyPassword(email, password);
            if (!passwordCorrect)
            {
                throw new ApplicationException("Invalid credentials");
            }

            return _jwtHandler.Create(user.Id);
        }

        public async Task<IdentityResult> ForgetPassword(string email)
        {
            var user = _userRepository.GetQueryable().Where(x => x.Login.Username.Equals(email)).FirstOrDefault();
            //TODO: Check 1 request per 5 mins 
            var timeNow = DateTime.Now.ToUniversalTime();
            var delay = user.ResetPasswordTokenExpiryDate - new TimeSpan(47, 55, 00);
            if (delay >= timeNow)
            {
                TimeSpan diff = timeNow.Subtract(delay.Value);
                throw new ApplicationException("Invalid credentials");
            }
            //end Check
            if (user == null || !(await _userRepository.IsEmailConfirmedAsync(user.Id)))
            {
                throw new ApplicationException("Invalid Email");
            }
            string token = await _userRepository.GeneratePasswordResetTokenAsync(user.Id);
            user.ResetPasswordToken = token;
            //user.ResetPasswordTokenExpiryDate = DateTime.Now.AddDays(2).ToUniversalTime();

            user.ResetPasswordTokenExpiryDate = DateTime.Now.AddHours(37); //Only for NZ time zone, 24hours + 13hours UTC time zone

           var result = await _userRepository.UpdateAsync(user);
            if (result.Succeeded)
            {
                var nvc = new NameValueCollection();
                nvc.Set("token", token);
                nvc.Set("email", email);
                string url = UriHelper.UrlGenerator(HttpContext.Current.Request, "Account/ResetPassword", StringHelpler.ToQueryString(nvc));
                string subject = "Reset Password";
                string body =
                    "Hello !<br />"
                    + "You (or someone else) just want to reset password for this email,<br />"
                    + "Please <a target='_blank' href=" + url + "> Click Here </a> to reset your password <br />"
                    + $"This link will expire on {user.ResetPasswordTokenExpiryDate}"; ;

                // Send email
                IdentityMessage message = new IdentityMessage
                {
                    Destination = user.Email,
                    Body = body,
                    Subject = subject,
                };
                try
                {
                    await _emailService.SendAsync(message);
                }
                catch (Exception ex)
                {
                    if (ex != null)
                    {
                       
                        throw new ApplicationException("Email Server Error");
                    }
                }
                return result;
            }
            return result;

        }




    }
    //needs to be moved//
    public class IdentityMessage
    {
        public object Destination { get; set; }
        public string Body { get; set; }
        public string Subject { get; set; }
    }
}
