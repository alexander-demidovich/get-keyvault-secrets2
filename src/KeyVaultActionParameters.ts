import util = require("util");
import * as core from '@actions/core';
import { IAuthorizer } from 'azure-actions-webclient/Authorizer/IAuthorizer';

export class KeyVaultActionParameters {

    public keyVaultName: string;
    public secretsFilter: string;
    public keyVaultUrl: string;
    public secretsFilePath: string;
    
    public getKeyVaultActionParametersForSpecificKeyVaultWithFile(handler: IAuthorizer, keyVault: string, secretsPath: string) : KeyVaultActionParameters {
      this.keyVaultName = keyVault;
      this.secretsFilePath = secretsPath;

      if (!this.keyVaultName) {
          core.setFailed("Vault name not provided.");
      }

      if (!this.secretsFilePath) {
        core.setFailed("SecretsFilePath should be provided");
      }

      var azureKeyVaultDnsSuffix = handler.getCloudSuffixUrl("keyvaultDns").substring(1);
      this.keyVaultUrl = util.format("https://%s.%s", this.keyVaultName, azureKeyVaultDnsSuffix);
      return this;
    }

    public getKeyVaultActionParameters(handler: IAuthorizer) : KeyVaultActionParameters {
        this.keyVaultName = core.getInput("keyvault");
        this.secretsFilter = core.getInput("secrets");
        this.secretsFilePath = core.getInput("secretsfile");

        if (!this.keyVaultName) {
            core.setFailed("Vault name not provided.");
        }

        if (this.secretsFilter && this.secretsFilePath) {
          core.setFailed("Both secretsFilter and secretsFilePath cannot be provided at the same time.");
        }

        if (!this.secretsFilter && !this.secretsFilePath) {
          core.setFailed("One of secretsFilter or secretsFilePath should be provided");
        }

        var azureKeyVaultDnsSuffix = handler.getCloudSuffixUrl("keyvaultDns").substring(1);
        this.keyVaultUrl = util.format("https://%s.%s", this.keyVaultName, azureKeyVaultDnsSuffix);
        return this;
    }
}
