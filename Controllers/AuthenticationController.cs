using Mars.Common.Commands;
using Mars.Common.Models;
using Mars.Common.Security;
using Mars.Services.Identity.Domain.Services;
using Mars.Services.Identity.ViewModels;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using RawRabbit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace Mars.Services.Identity.Controllers
{
    [Route("authentication/[controller]")]
    public class AuthenticationController : Controller
    {
        private readonly IBusClient _busClient;
        private readonly IAuthenticationService _authenticationService;
        private readonly IUserAppContext _userAppContext;
        public AuthenticationController(
              IBusClient busClient,
              IAuthenticationService authenticationService,
              IUserAppContext userAppContext)
        {
            _busClient = busClient;
            _authenticationService = authenticationService;
            _userAppContext = userAppContext;
        }
        [HttpPost("signup")]
        public async Task<IActionResult> Signup([FromBody]CreateUser command)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return Json(new { IsSuccess = false, Message = "Parameter can not be null" });
                }

                await _authenticationService.Register(new SignUpPersonal
                {
                    FirstName = command.FirstName,
                    LastName = command.LastName,
                    EmailAddress = command.Email,
                    Password = command.Password,
                    TermsConditionsAccepted = true
                });

                return Json(new { IsSuccess = true });
            }
            catch (ApplicationException e)
            {
                return Json(new { IsSuccess = false,  e.Message });
            }
        }

        [HttpPost("signin")]
        public async Task<IActionResult> SignIn([FromBody]CreateUser command)
        {
            try
            {
                var authenticateUser = await _authenticationService.LoginAsync(command.Email, command.Password);
                return Json(new { IsSuccess = true, Token = authenticateUser });
            }
            catch (ApplicationException e)
            {
                return Json(new { IsSuccess = false,  e.Message });
            }
        }

        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public IActionResult Get() {
            var userId = _userAppContext.CurrentUserId;
            return Content("Secured");
        }

        [HttpPost("forgetpassword")]
        public async Task<ActionResult> ForgetPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var authenticateUser = await _authenticationService.ForgetPassword(model.Email);
                if (authenticateUser.Succeeded)
                {
                    return Json(new
                    {
                        Success = true,
                        Email = model.Email,
                        MsgText = "Confirm Your Email !"
                    });
                }
                return Json(new
                {
                    Success = false,
                    model.Email,
                    Errors = authenticateUser.Errors,
                    MsgText = "Something went wrong"
                });
            }
            var errorList = ModelState.Values.SelectMany(m => m.Errors)
                                 .Select(e => e.ErrorMessage);
            return Json(new
            {
                Success = false,
                MsgText = "Something went wrong.",
                Errors = errorList,
                Email = model.Email
            });
        }
    }
}
