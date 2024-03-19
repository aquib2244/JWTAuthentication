using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
       public IConfiguration _configuration;

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [AllowAnonymous]
        [HttpPost]
        public IActionResult Auth([FromBody] User user)
        {
            IActionResult response = Unauthorized();

            if(user != null)
            {
                if(user.UserName.Equals("test@email.com") && user.Password.Equals("a"))
                {
                    var issuer = _configuration["Jwt:Issuer"];
                    var audience = _configuration["Jwt:Audience"];
                    var key = Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]);
                    var signcred = new SigningCredentials(new SymmetricSecurityKey(key),
                        SecurityAlgorithms.HmacSha512Signature);

                    var subject = new ClaimsIdentity(new[] 
                    {
                        new Claim(JwtRegisteredClaimNames.Sub,user.UserName),
                        new Claim(JwtRegisteredClaimNames.Email,user.UserName)
                    });

                    var expire = DateTime.UtcNow.AddMinutes(10);

                    var tokenDescriptor = new SecurityTokenDescriptor {
                        Subject = subject,
                        Expires = expire,
                        Issuer =issuer,
                        Audience = audience,
                        SigningCredentials = signcred
                    };

                    var tokenHandller = new JwtSecurityTokenHandler();
                    var token = tokenHandller.CreateToken(tokenDescriptor);
                    var jwtToken = tokenHandller.WriteToken(token);

                    return Ok(jwtToken);

                }
            }
            return response;
        }
    }
}
