using Mars.Common.Auth;
using Mars.Common.Models;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Mars.Services.Identity.Domain.Services
{
    public interface IAuthenticationService
    {
        Task Register(SignUpPersonal user);
        Task<bool> VerifyPassword(string email, string password);
        Task ResetPassword(Login user, string newPassword);
        Task<JsonWebToken> LoginAsync(string email, string password);
        Task<IdentityResult> ForgetPassword(string email);
        Task<IdentityResult> ResetPassword(string email, string token, string newPassword);
    }
}
