using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Identity;
using Amazon.AspNetCore.Identity.Cognito;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using WebAdvert.Web.Models.Accounts;
using Amazon.Runtime.Internal.Transform;

namespace WebAdvert.Web.Controllers
{
    public class Accounts : Controller
    {
        private readonly SignInManager<CognitoUser> _signInManager;
        private readonly UserManager<CognitoUser> _userManager;
        private readonly CognitoUserPool _pool;
        public Accounts(SignInManager<CognitoUser> signInManager, UserManager<CognitoUser> userManager, CognitoUserPool pool)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _pool = pool;
        }
        public IActionResult Signup()
        {
            var model = new SignupModel();
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Signup(SignupModel model)
        {
            if(!ModelState.IsValid)
            {
                var user = _pool.GetUser(model.Email);
                if (user.Status != null)
                {
                    ModelState.AddModelError("UserExists", "User with this email already exists");
                    return View(model);
                }
                
                user.Attributes.Add("Name", model.Email);
                var createdUser = await _userManager.CreateAsync(user, model.Password).ConfigureAwait(false);

                if (createdUser.Succeeded)
                    RedirectToAction("Confirm");
            }
            return View();
        }

        public IActionResult Confirm()
        {
            var model = new ConfirmModel();
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Confirm(ConfirmModel confirmModel)
        {
            if(ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(confirmModel.Email);
                if(user == null)
                {
                    ModelState.AddModelError("NotFound", "A user with the given email address was not found");
                    return View (confirmModel);
                }

                await (_userManager as CognitoUserManager<CognitoUser>).ConfirmSignUpAsync(user, confirmModel.Code, false).ConfigureAwait(false);
                var result = await _userManager.ConfirmEmailAsync(user, confirmModel.Code);
                if (result.Succeeded)
                {
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    foreach(var item in result.Errors)
                    {
                        ModelState.AddModelError(item.Code, item.Description);
                    }
                }
            }
            return View (confirmModel);
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginModel loginModel)
        {
            if(ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(loginModel.Email, loginModel.Password, loginModel.RememberMe, false).ConfigureAwait(false);
                if(result.Succeeded)
                {
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    ModelState.AddModelError("LoginError", "Email or Password do not match");
                }
            }
            return View(loginModel);
        }
    }
}
