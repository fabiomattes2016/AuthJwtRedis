using ApiAuth.Internals;
using ApiAuth.Models;
using Microsoft.IdentityModel.Tokens;
using ServiceStack.Redis;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace ApiAuth.Services
{
    public static class TokenService
    {
        // With User model
        public static string GenerateToken(User user)
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            byte[] key = Encoding.ASCII.GetBytes(Settings.Secret);
            SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(ClaimTypes.Role, user.Role)
                }),
                Expires = DateTime.UtcNow.AddHours(8),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }

        // With claims
        public static string GenerateToken(IEnumerable<Claim> claims)
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            byte[] key = Encoding.ASCII.GetBytes(Settings.Secret);
            SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddHours(8),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }

        public static string GenerateRefreshToken()
        {
            byte[] randomNumber = new byte[32];
            using RandomNumberGenerator rng = RandomNumberGenerator.Create();

            rng.GetBytes(randomNumber);

            return Convert.ToBase64String(randomNumber);
        }

        public static ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            byte[] key = Encoding.ASCII.GetBytes(Settings.Secret);

            TokenValidationParameters tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateLifetime = false,
            };

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            ClaimsPrincipal principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);

            if (securityToken is not JwtSecurityToken jwtSecurityToken ||
                !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid Token");

            return principal;
        }

        public static void SaveRefreshToken(string username, string refreshToken)
        {
            string host = Settings.redisHost;
            string pass = Settings.redisPassword;
            int port = Settings.redisPort;

            ClientRedis redis = new ClientRedis
            {
                Key = username,
                Name = username,
                Document = refreshToken,
            };

            using (RedisClient redisClient = new RedisClient(host, port, pass))
            {
                redisClient.Set<ClientRedis>(redis.Key, redis);
            }
        }

        public static string GetRefreshToken(string username)
        {
            string host = Settings.redisHost;
            string pass = Settings.redisPassword;
            int port = Settings.redisPort;

            using (RedisClient redisClient = new RedisClient(host, port, pass))
            {
                var tokens = redisClient.Get<ClientRedis>(username);

                return tokens.Document;
            }
        }

        public static void DeleteRefreshToken(string username)
        {
            string host = Settings.redisHost;
            string pass = Settings.redisPassword;
            int port = Settings.redisPort;

            using (RedisClient redisClient = new RedisClient(host, port, pass))
            {
                redisClient.Remove(username);
            }
        }
    }
}
