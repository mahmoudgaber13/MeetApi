using MeetApi.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using Microsoft.AspNetCore.Hosting;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using MeetApi.Services;

namespace MeetApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly IConfiguration _configuration;
        private readonly IWebHostEnvironment hosting;
        string FileName = string.Empty;
        private readonly PasswordRecovery passwordRecovery;

        public AuthenticateController(UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager, IConfiguration configuration
            , IWebHostEnvironment hosting, PasswordRecovery passwordRecovery)
        {
            this.passwordRecovery = passwordRecovery;
            this.userManager = userManager;
            this.roleManager = roleManager;
            _configuration = configuration;
            this.hosting = hosting;
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {

            var user = await userManager.FindByEmailAsync(model.Email);
            if (user != null && await userManager.CheckPasswordAsync(user, model.Password))
            {
                var userRoles = await userManager.GetRolesAsync(user);

                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }

                var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

                var token = new JwtSecurityToken(
                    issuer: _configuration["JWT:ValidIssuer"],
                    audience: _configuration["JWT:ValidAudience"],
                    expires: DateTime.Now.AddDays(365),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                    );

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo,
                    role = userRoles[0],
                    Image = user.Image,
                    UserName = user.Name,
                    Id = user.Id,
                    Email = user.Email
                });
            }
            return Unauthorized();


        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromForm] RegisterModel model)
        {
            var userExists = await userManager.FindByEmailAsync(model.Email);
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User already exists!" });
            FileName = (Guid.NewGuid().ToString() + model.Image.FileName);

            ApplicationUser user = new ApplicationUser()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Email,
                Name = model.Username,
                Image = FileName
            };
            var result = await userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });
            if (!await roleManager.RoleExistsAsync(UserRoles.Admin))
                await roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));
            if (!await roleManager.RoleExistsAsync(UserRoles.User))
                await roleManager.CreateAsync(new IdentityRole(UserRoles.User));

            if (await roleManager.RoleExistsAsync(UserRoles.Admin))
            {
                await userManager.AddToRoleAsync(user, UserRoles.User);
            }
            string uploads = Path.Combine(hosting.WebRootPath, "Uploads");
            string FullPath = Path.Combine(uploads, FileName);
            model.Image.CopyTo(new FileStream(FullPath, FileMode.Create));
            return Ok(new Response { Status = "Success", Message = "User created successfully!" });
        }


        [HttpPost]
        [Route("register-admin")]
        public async Task<IActionResult> RegisterAdmin([FromForm] RegisterModel model)
        {
            var userExists = await userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User already exists!" });
            FileName = (Guid.NewGuid().ToString() + model.Image.FileName);
            ApplicationUser user = new ApplicationUser()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Email,
                Name = model.Username,
                Image = FileName
            };
            var result = await userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });

            if (!await roleManager.RoleExistsAsync(UserRoles.Admin))
                await roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));
            if (!await roleManager.RoleExistsAsync(UserRoles.User))
                await roleManager.CreateAsync(new IdentityRole(UserRoles.User));

            if (await roleManager.RoleExistsAsync(UserRoles.Admin))
            {
                await userManager.AddToRoleAsync(user, UserRoles.Admin);
            }
            string uploads = Path.Combine(hosting.WebRootPath, "Uploads");

            string FullPath = Path.Combine(uploads, FileName);
            model.Image.CopyTo(new FileStream(FullPath, FileMode.Create));
            user.Image = FileName;
            return Ok(new Response { Status = "Success", Message = "User created successfully!" });
        }

        [HttpPut]
        [Route("PutUser")]
        public async Task<IActionResult> PutUser([FromForm] UpdateUser model)
        {
            try
            {
                var user = await userManager.FindByIdAsync(model.Id);
                if (model.Username != null)
                {
                    user.Name = model.Username;
                    await userManager.UpdateAsync(user);
                }
                if (model.Image != null)
                {        
                    string uploads = Path.Combine(hosting.WebRootPath, "Uploads");
                    FileName = (Guid.NewGuid().ToString() + model.Image.FileName);
                    string FullPath = Path.Combine(uploads, FileName);

                    var OldImage = Path.Combine(uploads, user.Image);
                    using (var stream = System.IO.File.Open(OldImage, FileMode.Open))
                    {
                        stream.Dispose();
                        System.IO.File.Delete(OldImage);
                    }

                    using (var stream = System.IO.File.Open(FullPath, FileMode.Create))
                    {
                        model.Image.CopyTo(stream);
                        stream.Dispose();
                    }



                    //model.Image.CopyTo(new FileStream(FullPath, FileMode.Create));
                    
                    user.Image = FileName;

                    await userManager.UpdateAsync(user);
                }
                if (model.Email != null)
                {
                    user.Email = model.Email;
                    user.UserName = model.Email;
                    await userManager.UpdateAsync(user);
                }
                await userManager.UpdateAsync(user);
                return Ok(new { Status = "Success", Message = "User Updated successfully!", Image = user.Image });
            }
            catch (Exception e)
            {
                return BadRequest(new Response { Status = "Failure", Message = e.Message });
            }

        }

        [HttpPut]
        [Route("PutPassword")]
        public async Task<IActionResult> PutPassword([FromForm] UpdatePassword model)
        {
            try
            {
                var user = await userManager.FindByIdAsync(model.Id);
                await userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);

                await userManager.UpdateAsync(user);
                return Ok(new Response { Status = "Success", Message = "User Updated successfully!" });
            }
            catch (Exception e)
            {
                return BadRequest(new Response { Status = "Failure", Message = e.Message });
            }
        }

        [HttpPost]
        [Route("ForgotPassword")]
        public async Task<IActionResult> ForgotPassword([FromForm] string Email)
        {
            try
            {
                var user = await userManager.FindByEmailAsync(Email);
                if (user != null)
                {
                    var Password = passwordRecovery.GeneratePassword(10);
                    //await userManager.ChangePasswordAsync(user, user.PasswordHash, Password);
                    var code = await userManager.GeneratePasswordResetTokenAsync(user);
                    var result = await userManager.ResetPasswordAsync(user, code, Password);
                    passwordRecovery.PasswordRecoveryMail(user, Password);
                    return Ok(new Response { Status = "Success", Message = "Check your email please" });
                }
                else
                {
                    return BadRequest(new Response { Status = "Failure" });
                }
            }
            catch (Exception e)
            {
                return BadRequest(new Response { Status = "Failure", Message = e.Message });
            }
        }
    }
}