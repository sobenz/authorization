﻿using System;

namespace Sobenz.Authorization.Models
{
    public class ClientSecret
    {
        public string Name { get; set; }
        public string SecretHash { get; set; }
        public DateTime ActiveFrom { get; set; }
        public DateTime ActiveTo { get; set; }
    }
}
