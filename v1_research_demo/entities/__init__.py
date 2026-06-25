# entities/ – Simulation actors.
#
# Each class here models a physical or logical device in the smart
# grid network.  The five actors are:
#
#   TTP             – Trusted Third Party (offline after setup)
#   SmartMeter      – Individual household meter
#   AggregationGateway – Edge server that aggregates encrypted data
#   ControlCenter   – The utility company's trusted computation node
#   CloudServer     – Third-party cloud for analytics
#
# The entity layer is an OOP wrapper around the purely functional
# schemes/ layer.  Each entity holds its own keys and state, and
# its methods delegate to the scheme functions with the right params.
#
# This separation matters because it maps directly to the paper's
# threat model: "who knows what" is defined by which keys each
# entity's __init__ receives.
