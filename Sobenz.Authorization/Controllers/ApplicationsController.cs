using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sobenz.Authorization.Interfaces;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class ApplicationsController : ControllerBase
    {
        private readonly IApplicationService _applicationService;

        public ApplicationsController(IApplicationService applicationService)
        {
            _applicationService = applicationService ?? throw new ArgumentNullException(nameof(applicationService));
        }

        [HttpGet]
        public async Task<IActionResult> List(CancellationToken cancellationToken = default)
        {
            var apps = await _applicationService.List(cancellationToken);
            return Ok(apps);
        }
    }
}
