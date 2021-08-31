﻿using System;

namespace Sobenz.Authorization.Models
{
    public class PersistedTokenOptions
    {
        public TimeSpan AuthorizationCodeLifetime { get; set; }
        public TimeSpan RefreshTokenLifetime { get; set; }
        public TimeSpan UserSessionLifetime { get; set; }

    }
}
