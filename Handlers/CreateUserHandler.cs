﻿using Mars.Common.Commands;
using Mars.Common.Events;
using Mars.Services.Identity.Domain.Services;
using RawRabbit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Mars.Services.Identity.Handlers
{
    public class CreateUserHandler: ICommandHandler<CreateUser>
    {
        private readonly IBusClient _busClient;
        private readonly IAuthenticationService _authenticationService;

        public CreateUserHandler(IBusClient busClient,
            IAuthenticationService authenticationService)
        {
            _busClient = busClient;
            _authenticationService = authenticationService;
        }

        public async Task HandleAsync(CreateUser command)
        {
            try
            {
                Console.WriteLine("Creating user");
                await _authenticationService.Register(new Common.Models.SignUpPersonal
                {
                    FirstName = command.FirstName,
                    EmailAddress = command.Email,
                    Password = command.Password,
                    TermsConditionsAccepted = true
                });
                await _busClient.PublishAsync(new UserCreated(command.Email, command.FirstName));
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                throw;
            }
           
        }
    }
}
