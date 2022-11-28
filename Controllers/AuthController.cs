using System.Text;
using Microsoft.IdentityModel.Tokens;
using jwt.Model;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authorization;

namespace jwt.Controller;
[ApiController]
[Route("api/[controller]")]
public class AuthController:ControllerBase
{
    private readonly IConfiguration _config;

    public AuthController(IConfiguration config)
    {
        _config=config;
    }

    [HttpPost]
    [AllowAnonymous]
    public IActionResult Login([FromBody]UserLogin userLogin)
    {
        var user=Authenticate(userLogin);
        if(user !=null)
        {
            var token = GenerateToken(user);
            return Ok(token);
        }
        return NotFound("User Not found");
    }

    private string GenerateToken(UserModel user)
    {
        var securityKey=new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
        var credentials=new SigningCredentials(securityKey,SecurityAlgorithms.HmacSha256);
        var claims=new[]
            {
            new Claim(ClaimTypes.NameIdentifier,user.UserName),
            new Claim(ClaimTypes.Role,user.Role)
            };

        var token= new JwtSecurityToken(
            _config["Jwt:Issuer"],
            _config["Jwt:Audience"],
            claims,
            expires:DateTime.Now.AddSeconds(10),
            signingCredentials:credentials
        );
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private UserModel? Authenticate(UserLogin model)
    {
        var userFromDb=UserConstants.Users.FirstOrDefault(x=>x.UserName.ToLower()==model.UserName.ToLower()&&x.Password==model.Password);
        if (userFromDb!=null)
        {
            return userFromDb;
        }
        return null;
    }
    
}