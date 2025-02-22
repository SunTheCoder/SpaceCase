import { Image } from '@chakra-ui/react';
import { Button } from '../ui/button';
import { Tooltip } from '../ui/tooltip';

const MetamaskButton = () => (
    <Tooltip
      content="Install Metamask"
    >
      <Button main size="xs" onClick={() => window.open("https://metamask.io/download.html", "_blank")}>
        <Image p="4px" src="../../../public/metamaskicon.svg" alt="Metamask Icon" style={{ width: '40px', height: '40px' }} />
      </Button>
    </Tooltip>
);

export default MetamaskButton;
