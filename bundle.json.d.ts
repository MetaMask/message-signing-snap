declare module "bundle.json" {
  interface Bundle {
    bundle: string;
    icon: string;
    manifest: {
      version: string;
      description: string;
      proposedName: string;
      repository: {
        type: string;
        url: string;
      };
      source: {
        shasum: string;
        location: {
          npm: {
            filePath: string;
            iconPath: string;
            packageName: string;
            registry: "https://registry.npmjs.org/";
          };
        };
      };
      initialPermissions: {
        snap_getEntropy: {};
        "endowment:rpc": {
          dapps: boolean;
          snaps: boolean;
        };
      };
      manifestVersion: string;
    };
  }

  const bundle: Bundle;
  export default bundle;
}