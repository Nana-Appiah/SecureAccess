using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace SecureAuth.Models
{
    public class User
    {
        public int Id { get; set; }
        public string username { get; set; }
        public string pass { get; set; }
    }
}