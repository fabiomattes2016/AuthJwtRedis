using ApiAuth.Models;
using System;
using System.Collections.Generic;
using System.Linq;

namespace ApiAuth.Repositories
{
    public class UserRepository
    {
        public static User Get(string username, string password)
        {
            var users = new List<User>
            {
                new() { Id = 1, UserName = "fabiomattes", Password = "12345678", Role = "admin" },
                new() { Id = 2, UserName = "usuario", Password = "12345678", Role = "user" }
            };

            return users.FirstOrDefault(u => 
                string.Equals(u.UserName, username, StringComparison.CurrentCultureIgnoreCase) 
                && u.Password == password);
        }
    }
}
