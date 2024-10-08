import * as core from '@actions/core';
import * as crypto from "crypto";
import { AuthorizerFactory } from 'azure-actions-webclient/AuthorizerFactory';
import { IAuthorizer } from 'azure-actions-webclient/Authorizer/IAuthorizer';
import { KeyVaultActionParameters } from './KeyVaultActionParameters';
import { KeyVaultHelper } from './KeyVaultHelper';
import * as exec from '@actions/exec';
import * as io from '@actions/io';

var azPath: string;
var prefix = !!process.env.AZURE_HTTP_USER_AGENT ? `${process.env.AZURE_HTTP_USER_AGENT}` : "";
async function run() {
    try {
        let usrAgentRepo = crypto.createHash('sha256').update(`${process.env.GITHUB_REPOSITORY}`).digest('hex');
        let actionName = 'GetKeyVaultSecrets';
        let userAgentString = (!!prefix ? `${prefix}+` : '') + `GITHUBACTIONS_${actionName}_${usrAgentRepo}`;
        core.exportVariable('AZURE_HTTP_USER_AGENT', userAgentString);

        let handler: IAuthorizer = null;

        try {
            handler = await AuthorizerFactory.getAuthorizer();
        }
        catch (error) {
            core.setFailed("Could not login to Azure.")
        }

        if (handler != null) {
          
            azPath = await io.which("az", true);
            var environment = await executeAzCliCommand("cloud show --query name");
            environment = environment.replace(/"|\s/g, '');
            console.log('Running keyvault action against ' + environment);
            var keyVaultName = core.getInput("keyvault").trim();
            var secrets = core.getInput("secrets").trim();
            if (keyVaultName && secrets)
            {
                // this code works only when keyvault and secrets are provided as input, for backward compatibility with the version 2
                console.log('Running keyvault action against input param ' + keyVaultName);
                console.log('Running keyvault action against with secrets ' + secrets);

                var actionParameters = new KeyVaultActionParameters().getKeyVaultActionParameters(handler);
                await downloadSecrets(handler, environment, actionParameters);
            }
           
            var keyVaultPairsInput = core.getInput("key_vault_with_secret_file_pairs")
            if (keyVaultPairsInput){            
                // param key_vault_with_secret_file_pairs in github action looks like this:
                //      key_vault_with_secret_file_pairs: |
                //          infra-eu-dev-kv=.github/env/eu/dev/key_vault1.env,
                //          business-eu-dev-kv=.github/env/eu/dev/key_vault2.env
                var keyVaultPairs = keyVaultPairsInput.split(',');

                for (var i = 0; i < keyVaultPairs.length; i++) {
                    var keyVaultPair = keyVaultPairs[i].trim().split('=');
                    var keyVault = keyVaultPair[0].trim();
                    var secretsFilePath = keyVaultPair[1].trim();
                    console.log('Running keyvault action against ' + keyVault);
                    console.log('Running keyvault action against with secret file ' + secretsFilePath);

                    var actionParameters = new KeyVaultActionParameters().getKeyVaultActionParametersForSpecificKeyVaultWithFile(handler, keyVault, secretsFilePath);
                    await downloadSecrets(handler, environment, actionParameters);
                }
            }
        }        
    } catch (error) {
        core.debug("Get secret failed with error: " + error);
        core.setFailed(!!error.message ? error.message : "Error occurred in fetching the secrets.");
    }
    finally {
        core.exportVariable('AZURE_HTTP_USER_AGENT', prefix);
    }
}

async function downloadSecrets(handler: IAuthorizer, environment: string, actionParameters: KeyVaultActionParameters) {
    var keyVaultHelper = new KeyVaultHelper(handler, 100, actionParameters);
    if (environment.toLowerCase() == "azurestack") {
        await keyVaultHelper.initKeyVaultClient();
    }
    keyVaultHelper.downloadSecrets();
}

async function executeAzCliCommand(command: string) {
    let stdout = '';
    let stderr = '';
    try {
        core.debug(`"${azPath}" ${command}`);
        await exec.exec(`"${azPath}" ${command}`, [], {
            silent: true, // this will prevent priniting access token to console output
            listeners: {
                stdout: (data: Buffer) => { stdout += data.toString(); },
                stderr: (data: Buffer) => { stderr += data.toString(); }
            }
        });
    } catch (error) {
        throw new Error(stderr);
    }
    return stdout;
}

run();