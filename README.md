<h1>Intune Enrollment: Windows Device Silent Enrollment.</h1>

<p>Silently enroll a Windows device to Microsoft Intune <span style="text-decoration: underline;"><strong>if already joined to Azure AD and already has an AAD user account.</strong> </span></p>
<p>Will help automatically enroll existing Windows devices (Hybrid or Azure AD joined) into Intune. Verifies if device is Azure AD join, that has an Azure AD account from same Tenant and verifies that Intune services do not already exist on device. If so, it configures MDM urls and executes Device Enrollment.</p>
<p>Logic based on Rudy Ooms (<a href="https://twitter.com/Mister_MDM">@Mister_MDM</a>) blog: <a href="https://call4cloud.nl/2020/05/intune-auto-mdm-enrollment-for-devices-already-azure-ad-joined/">https://call4cloud.nl/2020/05/intune-auto-mdm-enrollment-for-devices-already-azure-ad-joined/ </a>.</p>


<h3>Added verifications:</h3>

<ul>
<li>Validate admin privilige.</li>
<li>Confirm device is AzureAD joined.</li>
<li>Confirm user information from same Tenant as device.</li>
<li>Execute enrollment as system.</li>
</ul>


<p>Function to execute as SYSTEM from Ondrej Sebela (<a href="https://twitter.com/AndrewZtrhgf">@AndrewZtrhgf</a>), described in the following blog: <a href="https://doitpsway.com/fixing-hybrid-azure-ad-join-on-a-device-using-powershell">https://doitpsway.com/fixing-hybrid-azure-ad-join-on-a-device-using-powershell</a> Source: <a href="https://github.com/ztrhgf/useful_powershell_functions/blob/master/INTUNE/Reset-HybridADJoin.ps1">https://github.com/ztrhgf/useful_powershell_functions/blob/master/INTUNE/Reset-HybridADJoin.ps1</a></p>
<p>Other source: <a href="https://nerdymishka.com/articles/azure-ad-domain-join-registry-keys/ ">https://nerdymishka.com/articles/azure-ad-domain-join-registry-keys/</a></p>
<p>More sources mentioned in code.</p>


<h4>To do:</h4>
<ul>
<li>At end verify that Device correctly received Intune Certificate.</li>
</ul>
