import { PluginInitializerContext, CoreSetup, CoreStart, Plugin, Logger } from '@kbn/core/server';

import { schema } from '@kbn/config-schema';
import { ConfigSchema } from '../common';

export class TigeraPlugin implements Plugin {
  private readonly logger: Logger;
  constructor(private readonly initializerContext: PluginInitializerContext<ConfigSchema>) {
    this.logger = initializerContext.logger.get();
  }

  public setup(core: CoreSetup) {
    this.logger.debug('Tigera plugin setup')
    const config$ = this.initializerContext.config.create();
    config$.subscribe((config) => {
      core.uiSettings.register({
        'tigeratagmanager.licenseEdition': {
          value: config.licenseEdition,
          schema: schema.string(),
        },
      });
    });
  }

  public start(core: CoreStart) {
    this.logger.debug('Tigera plugin start up')
    return {};
  }

  public stop() {}
}
