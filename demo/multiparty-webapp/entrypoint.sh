#!/bin/sh

# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright 2026 The OpenHTTPA Foundation (AIQL.org)

#!/bin/sh

# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright 2026 The OpenHTTPA Foundation (AIQL.org)

#!/bin/sh

# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright 2026 The OpenHTTPA Authors (AIQL.org)

#!/bin/sh

# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright 2026 AIQL Project

#!/bin/sh

# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright 2026 AIQL Project


# SPDX-License-Identifier: Apache-2.0 OR MIT



# entrypoint.sh - Start the backend and nginx in a single container.

# Start the Axum backend in the background.
/usr/local/bin/multiparty-webapp-backend &

# Start nginx in the foreground.
nginx -g "daemon off;"
